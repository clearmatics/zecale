// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/aggregator_circuit_wrapper.hpp"
#include "libzecale/circuits/groth16_verifier/groth16_verifier_parameters.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"
#include "libzecale/tests/circuits/dummy_application.hpp"

#include <gtest/gtest.h>

using namespace libzecale;

namespace
{

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

template<typename nsnarkT, typename wppT, typename wverifierT>
void test_aggregate_dummy_application()
{
    using nppT = other_curve<wppT>;
    using wsnarkT = typename wverifierT::snark;

    static const size_t batch_size = 2;
    static const size_t public_inputs_per_proof = 1;

    // Nested keypair and proofs
    test::dummy_app_wrapper<nppT, nsnarkT> dummy_app;
    const typename nsnarkT::keypair nkp = dummy_app.generate_keypair();

    const libzeth::extended_proof<nppT, nsnarkT> npf1 =
        dummy_app.prove(5, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf1.get_primary_inputs().size());
    std::cout << "NESTED_PROOF 1:\n";
    npf1.write_json(std::cout);

    const libzeth::extended_proof<nppT, nsnarkT> npf2 =
        dummy_app.prove(9, nkp.pk);
    ASSERT_EQ(public_inputs_per_proof, npf2.get_primary_inputs().size());
    std::cout << "\nNESTED_PROOF 2:\n";
    npf2.write_json(std::cout);

    // Wrapper keypair
    aggregator_circuit_wrapper<nppT, wppT, nsnarkT, wverifierT, batch_size>
        aggregator(public_inputs_per_proof);
    const typename wsnarkT::keypair wkeypair =
        aggregator.generate_trusted_setup();

    // Create a batch and create a wrapping proof for it
    std::array<const libzeth::extended_proof<nppT, nsnarkT> *, batch_size>
        batch{&npf1, &npf2};
    const libzeth::extended_proof<wppT, wsnarkT> wpf =
        aggregator.prove(nkp.vk, batch, wkeypair.pk);

    ASSERT_TRUE(wsnarkT::verify(
        wpf.get_primary_inputs(), wpf.get_proof(), wkeypair.vk));

    std::cout << "\nWRAPPING PROOF:\n";
    wpf.write_json(std::cout);

    // TOOD: Enable once aggregator gadget is fixed
#if 0
    // Check the inputs
    libff::Fr<wppT> winput1;
    fp_from_fp(winput1, npf1.get_primary_inputs()[0]);
    libff::Fr<wppT> winput2;
    fp_from_fp(winput2, npf2.get_primary_inputs()[0]);

    const libsnark::r1cs_primary_input<libff::Fr<wppT>> winputs =
        wpf.get_primary_inputs();
    ASSERT_EQ(winput1, winputs[0]);
    ASSERT_EQ(libff::Fr<wppT>::one(), winputs[1]);
    ASSERT_EQ(winput2, winputs[2]);
    ASSERT_EQ(libff::Fr<wppT>::one(), winputs[3]);
#endif
}

TEST(AggregatorTest, AggregateDummyApplicationMnt4Mnt6Groth16)
{
    using wpp = libff::mnt6_pp;
    using wverifier = groth16_verifier_parameters<wpp>;
    using npp = other_curve<wpp>;
    using nsnark = libzeth::groth16_snark<npp>;
    test_aggregate_dummy_application<nsnark, wpp, wverifier>();
}

TEST(AggregatorTest, AggregateDummyApplicationBls12Bw6Groth16)
{
    using wpp = libff::bw6_761_pp;
    using wverifier = groth16_verifier_parameters<wpp>;
    using npp = other_curve<wpp>;
    using nsnark = libzeth::groth16_snark<npp>;
    test_aggregate_dummy_application<nsnark, wpp, wverifier>();
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
