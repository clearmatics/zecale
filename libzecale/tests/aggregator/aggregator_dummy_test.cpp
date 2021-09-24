// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/aggregator_circuit.hpp"
#include "libzecale/circuits/groth16_verifier/groth16_verifier_parameters.hpp"
#include "libzecale/circuits/null_hash_gadget.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pghr13_verifier/pghr13_verifier_parameters.hpp"
#include "libzecale/tests/circuits/dummy_application.hpp"

#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/pairing/bw6_761_bls12_377/bw6_761_pairing_params.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/mnt/mnt_pairing_params.hpp>
#include <libzeth/circuits/blake2s/blake2s.hpp>

using namespace libzecale;

namespace
{

template<typename nppT, typename nsnarkT, size_t batch_size>
using proof_batch =
    std::array<const libzeth::extended_proof<nppT, nsnarkT> *, batch_size>;

template<
    mp_size_t wn,
    const libff::bigint<wn> &wmodulus,
    mp_size_t nn,
    const libff::bigint<nn> &nmodulus>
void fp_from_fp(
    libff::Fp_model<wn, wmodulus> &wfp,
    const libff::Fp_model<nn, nmodulus> &nfp)
{
    libff::bigint<wn> wint;
    const libff::bigint<nn> nint = nfp.as_bigint();
    assert(wint.max_bits() >= nint.max_bits());
    for (size_t limb_idx = 0; limb_idx < nn; ++limb_idx) {
        wint.data[limb_idx] = nint.data[limb_idx];
    }

    wfp = libff::Fp_model<wn, wmodulus>(wint);
}

template<typename FieldT, size_t length>
FieldT fp_from_bits(const std::array<FieldT, length> &bits)
{
    FieldT v = FieldT::zero();
    const FieldT two = FieldT::one() + FieldT::one();
    for (size_t i = 0; i < length; ++i) {
        if (bits[i] == FieldT::one()) {
            v += two ^ i;
        }
    }
    return v;
}

template<
    typename wppT,
    typename wsnarkT,
    typename nverifierT,
    size_t batch_size>
void test_aggregator_with_batch(
    const size_t num_inputs_per_nested_proof,
    const typename nverifierT::snark::keypair &nkp,
    const proof_batch<
        libsnark::other_curve<wppT>,
        typename nverifierT::snark,
        batch_size> &batch,
    const typename wsnarkT::keypair &wkeypair,
    aggregator_circuit<wppT, wsnarkT, nverifierT, batch_size> &aggregator,
    const std::array<libff::Fr<wppT>, batch_size> &expected_results)
{
    using npp = libsnark::other_curve<wppT>;

    // Generate proof and check it.
    const libzeth::extended_proof<wppT, wsnarkT> wpf =
        aggregator.prove(nkp.vk, batch, wkeypair.pk);
    std::cout << "\nWRAPPING PROOF:\n";
    wpf.write_json(std::cout);
    ASSERT_TRUE(wsnarkT::verify(
        wpf.get_primary_inputs(), wpf.get_proof(), wkeypair.vk));

    // Check the inputs
    const libsnark::r1cs_primary_input<libff::Fr<wppT>> &winputs =
        wpf.get_primary_inputs();
    size_t winput_idx = 0;

    // Check the nested vk hash
    libff::Fr<wppT> expect_nested_vk_hash =
        verification_key_scalar_hash_gadget<wppT, nverifierT>::compute_hash(
            nkp.vk, num_inputs_per_nested_proof);
    ASSERT_EQ(expect_nested_vk_hash, winputs[winput_idx]);
    ++winput_idx;

    // Packed results
    libff::Fr<wppT> expect_packed_results = fp_from_bits(expected_results);
    std::cout << "expect_packed_results: ";
    libzeth::field_element_write_json(expect_packed_results, std::cout);
    std::cout << "\nwinputs[winput_idx]: ";
    libzeth::field_element_write_json(winputs[winput_idx], std::cout);
    std::cout << "\n";

    ASSERT_EQ(expect_packed_results, winputs[winput_idx]);
    ++winput_idx;

    for (size_t proof_idx = 0; proof_idx < batch_size; ++proof_idx) {
        // Check that each input from the batch appears as expected in the
        // nested primary input list.
        for (const libff::Fr<npp> &ninput :
             batch[proof_idx]->get_primary_inputs()) {
            libff::Fr<wppT> ninput_w;
            fp_from_fp(ninput_w, ninput);
            ASSERT_EQ(ninput_w, winputs[winput_idx++]);
        }
    }
}

template<typename wppT, typename wsnarkT, typename nverifierT>
void test_aggregate_dummy_application()
{
    using npp = libsnark::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    static const size_t batch_size = 2;
    static const size_t public_inputs_per_proof = 1;

    // Nested keypair and proofs
    test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const typename nsnark::keypair nkp = dummy_app.generate_keypair();

    const libzeth::extended_proof<npp, nsnark> npf1 =
        dummy_app.prove(5, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf1.get_primary_inputs().size());
    std::cout << "NESTED_PROOF 1:\n";
    npf1.write_json(std::cout);

    const libzeth::extended_proof<npp, nsnark> npf2 =
        dummy_app.prove(9, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf2.get_primary_inputs().size());
    std::cout << "\nNESTED_PROOF 2:\n";
    npf2.write_json(std::cout);

    // Wrapper keypair
    aggregator_circuit<wppT, wsnarkT, nverifierT, batch_size> aggregator(
        public_inputs_per_proof);
    const typename wsnarkT::keypair wkeypair =
        aggregator.generate_trusted_setup();

    // Create and check a batched proof.
    test_aggregator_with_batch(
        public_inputs_per_proof,
        nkp,
        {{&npf1, &npf2}},
        wkeypair,
        aggregator,
        {libff::Fr<wppT>::one(), libff::Fr<wppT>::one()});
}

template<typename wppT, typename wsnarkT, typename nverifierT>
void test_aggregate_dummy_application_with_invalid_proof()
{
    using npp = libsnark::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    static const size_t batch_size = 2;
    static const size_t public_inputs_per_proof = 1;

    // Nested keypair and proofs
    test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const typename nsnark::keypair nkp = dummy_app.generate_keypair();

    const libzeth::extended_proof<npp, nsnark> npf1 =
        dummy_app.prove(5, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf1.get_primary_inputs().size());
    std::cout << "NESTED_PROOF 1:\n";
    npf1.write_json(std::cout);

    const libzeth::extended_proof<npp, nsnark> npf2 =
        dummy_app.prove(9, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf2.get_primary_inputs().size());
    // Corrupt the 2nd proof by copying the proof and inputs and adjusting.
    typename nsnark::proof proof2 = npf2.get_proof();
    libsnark::r1cs_primary_input<libff::Fr<npp>> inputs2 =
        npf2.get_primary_inputs();
    inputs2[0] = inputs2[0] + libff::Fr<npp>::one();
    const libzeth::extended_proof<npp, nsnark> npf2_invalid =
        libzeth::extended_proof<npp, nsnark>(std::move(proof2), {inputs2[0]});

    std::cout << "\nNESTED_PROOF 2:\n";
    npf2_invalid.write_json(std::cout);

    // Wrapper keypair
    aggregator_circuit<wppT, wsnarkT, nverifierT, batch_size> aggregator(
        public_inputs_per_proof);
    const typename wsnarkT::keypair wkeypair =
        aggregator.generate_trusted_setup();

    // Create and check a batched proof
    test_aggregator_with_batch(
        public_inputs_per_proof,
        nkp,
        {{&npf1, &npf2_invalid}},
        wkeypair,
        aggregator,
        {libff::Fr<wppT>::one(), libff::Fr<wppT>::zero()});
}

TEST(AggregatorTest, AggregateDummyApplicationMnt4Groth16Mnt6Groth16)
{
    using wpp = libff::mnt6_pp;
    using wsnark = libzeth::groth16_snark<wpp>;
    using nverifier = groth16_verifier_parameters<wpp>;
    test_aggregate_dummy_application<wpp, wsnark, nverifier>();
    test_aggregate_dummy_application_with_invalid_proof<
        wpp,
        wsnark,
        nverifier>();
}

TEST(AggregatorTest, AggregateDummyApplicationBls12Groth16Bw6Groth16)
{
    using wpp = libff::bw6_761_pp;
    using wsnark = groth16_snark<wpp>;
    using nverifier = groth16_verifier_parameters<wpp>;
    test_aggregate_dummy_application<wpp, wsnark, nverifier>();
    test_aggregate_dummy_application_with_invalid_proof<
        wpp,
        wsnark,
        nverifier>();
}

TEST(AggregatorTest, AggregateDummyApplicationBls12Groth16Bw6Pghr13)
{
    using wpp = libff::bw6_761_pp;
    using wsnark = libzeth::pghr13_snark<wpp>;
    using nverifier = groth16_verifier_parameters<wpp>;
    test_aggregate_dummy_application<wpp, wsnark, nverifier>();
    test_aggregate_dummy_application_with_invalid_proof<
        wpp,
        wsnark,
        nverifier>();
}

// Note, the verification gadgets for pghr13 as the nested proof scheme (from
// libsnark) can only be used with the mnt variable gadgets. Hence, without
// some refactoring, we cannot write tests
// AggregateDummyApplicationBls12Pghr13Bw6{Groth16,Pghr13}

TEST(AggregatorTest, AggregateDummyApplicationMnt4Pghr13Mnt6Groth16)
{
    using wpp = libff::mnt6_pp;
    using wsnark = libzeth::groth16_snark<wpp>;
    using nverifier = pghr13_verifier_parameters<wpp>;
    test_aggregate_dummy_application<wpp, wsnark, nverifier>();
    test_aggregate_dummy_application_with_invalid_proof<
        wpp,
        wsnark,
        nverifier>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();

    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
