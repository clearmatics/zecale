// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/groth16_verifier/groth16_verifier_parameters.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"
#include "libzecale/circuits/pghr13_verifier/pghr13_verifier_parameters.hpp"
#include "libzecale/circuits/verification_key_hash_gadget.hpp"
#include "libzecale/tests/circuits/dummy_application.hpp"

#include <gtest/gtest.h>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libzeth/circuits/blake2s/blake2s.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

namespace
{

template<typename wppT, typename nverifierT>
static void verification_key_scalar_hash_test()
{
    using FieldT = libff::Fr<wppT>;
    using npp = libzecale::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    // Get 2 VKs for the dummy app, and determine the number of primary inputs.
    libzecale::test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const size_t num_inputs =
        libzecale::test::dummy_app_wrapper<npp, nsnark>::num_primary_inputs;
    const typename nsnark::keypair nkeypair1 = dummy_app.generate_keypair();
    const typename nsnark::keypair nkeypair2 = dummy_app.generate_keypair();

    // Compute the digest of each key, as a scalar.
    const FieldT vk1_hash =
        libzecale::verification_key_scalar_hash_gadget<wppT, nverifierT>::
            compute_hash(nkeypair1.vk, num_inputs);
    const FieldT vk2_hash =
        libzecale::verification_key_scalar_hash_gadget<wppT, nverifierT>::
            compute_hash(nkeypair2.vk, num_inputs);

    // The digests should be non-zero, and different from each other with
    // overwhelming probability.
    ASSERT_NE(FieldT::zero(), vk1_hash);
    ASSERT_NE(FieldT::zero(), vk2_hash);
    ASSERT_NE(vk1_hash, vk2_hash);
}

TEST(VerificationKeyHashTest, ScalarHashTestBW6_761Groth16)
{
    using wpp = libff::bw6_761_pp;
    verification_key_scalar_hash_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>>();
}

TEST(VerificationKeyHashTest, ScalarHashTestBW6_761Pghr13)
{
    using wpp = libff::bw6_761_pp;
    verification_key_scalar_hash_test<
        wpp,
        libzecale::pghr13_verifier_parameters<wpp>>();
}

template<typename wppT, typename nverifierT>
void verification_key_scalar_hash_gadget_test()
{
    using FieldT = libff::Fr<wppT>;
    using npp = libzecale::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    const size_t num_nested_inputs =
        libzecale::test::dummy_app_wrapper<npp, nsnark>::num_primary_inputs;
    libzecale::test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const typename nsnark::keypair nkeypair = dummy_app.generate_keypair();

    // Compute the hash via the static compute method.
    const FieldT nvk_hash_value =
        libzecale::verification_key_scalar_hash_gadget<wppT, nverifierT>::
            compute_hash(nkeypair.vk, num_nested_inputs);

    // Set up a protoboard with hash as primary input.
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<libff::Fr<wppT>> nvk_hash;
    nvk_hash.allocate(pb, "nvk_hash");
    pb.set_input_sizes(1);

    // Verification key
    typename nverifierT::verification_key_scalar_variable_gadget nvk(
        pb, num_nested_inputs, "nvk");

    // Gadget to check the hash
    libzecale::verification_key_scalar_hash_gadget<wppT, nverifierT>
        nvk_hash_gadget(pb, nvk, nvk_hash, "nvk_scalar_hash_gadget");

    // Constraints
    nvk.generate_r1cs_constraints();
    nvk_hash_gadget.generate_r1cs_constraints();

    // Witness
    nvk.generate_r1cs_witness(nkeypair.vk);
    nvk_hash_gadget.generate_r1cs_witness();

    // Show final hash value in Fr<wppT>.
    const libff::Fr<wppT> hash_value = pb.val(nvk_hash);
    std::cout << "\nVK scalar hash value: ";
    libzeth::field_element_write_json(hash_value, std::cout);
    std::cout << "\n";

    ASSERT_EQ(nvk_hash_value, hash_value);
    ASSERT_NE(FieldT::zero(), hash_value);
}

TEST(VerificationKeyHashTest, ScalarHashGadgetTestBW6_761Groth16)
{
    using wpp = libff::bw6_761_pp;
    verification_key_scalar_hash_gadget_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>>();
}

TEST(VerificationKeyHashTest, ScalarHashGadgetTestBW6_761Pghr13)
{
    using wpp = libff::bw6_761_pp;
    verification_key_scalar_hash_gadget_test<
        wpp,
        libzecale::pghr13_verifier_parameters<wpp>>();
}

TEST(VerificationKeyHashTest, ScalarHashGadgetTestMNT4Groth16)
{
    using wpp = libff::mnt4_pp;
    verification_key_scalar_hash_gadget_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>>();
}

TEST(VerificationKeyHashTest, ScalarHashGadgetTestMNT6Groth16)
{
    using wpp = libff::mnt6_pp;
    verification_key_scalar_hash_gadget_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>>();
}

template<typename wppT, typename nverifierT, typename hash_gadgetT>
static void verification_key_hash_test()
{
    using FieldT = libff::Fr<wppT>;
    using npp = libzecale::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    libzecale::test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const size_t num_inputs =
        libzecale::test::dummy_app_wrapper<npp, nsnark>::num_primary_inputs;
    const typename nsnark::keypair nkeypair1 = dummy_app.generate_keypair();
    const typename nsnark::keypair nkeypair2 = dummy_app.generate_keypair();

    const FieldT vk1_hash = libzecale::verification_key_hash_gadget<
        wppT,
        nverifierT,
        hash_gadgetT>::compute_hash(nkeypair1.vk, num_inputs);
    const FieldT vk2_hash = libzecale::verification_key_hash_gadget<
        wppT,
        nverifierT,
        hash_gadgetT>::compute_hash(nkeypair2.vk, num_inputs);

    ASSERT_NE(vk1_hash, vk2_hash);
}

template<typename wppT, typename nverifierT, typename hash_gadgetT>
void verification_key_hash_gadget_test()
{
    using FieldT = libff::Fr<wppT>;
    using npp = libzecale::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    const size_t num_nested_inputs =
        libzecale::test::dummy_app_wrapper<npp, nsnark>::num_primary_inputs;
    libzecale::test::dummy_app_wrapper<npp, nsnark> dummy_app;
    const typename nsnark::keypair nkeypair = dummy_app.generate_keypair();

    // Compute the hash via the static compute method.
    const FieldT nvk_hash_value = libzecale::verification_key_hash_gadget<
        wppT,
        nverifierT,
        hash_gadgetT>::compute_hash(nkeypair.vk, num_nested_inputs);

    // Set up a protoboard with hash as primary input.
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<libff::Fr<wppT>> nvk_hash;
    nvk_hash.allocate(pb, "nvk_hash");
    pb.set_input_sizes(1);

    // Verification key and bits
    const size_t num_bits =
        nverifierT::verification_key_variable_gadget::size_in_bits(
            num_nested_inputs);
    std::cout << "VK variable requires " << std::to_string(num_bits)
              << " bits.\n";
    libsnark::pb_variable_array<FieldT> nvk_bits;
    nvk_bits.allocate(pb, num_bits, "nvk_bits");

    typename nverifierT::verification_key_variable_gadget nvk(
        pb, nvk_bits, num_nested_inputs, "nvk");

    // Gadget to check the hash
    libzecale::verification_key_hash_gadget<wppT, nverifierT, hash_gadgetT>
        nvk_hash_gadget(pb, nvk, nvk_hash, "nvk_hash_gadget");

    // Constraints

    nvk.generate_r1cs_constraints(true);
    nvk_hash_gadget.generate_r1cs_constraints();

    // Witness

    nvk.generate_r1cs_witness(nkeypair.vk);
    nvk_hash_gadget.generate_r1cs_witness();

    // Show final hash value in Fr<wppT>.

    const libff::Fr<wppT> hash_value = pb.val(nvk_hash);
    std::cout << "\nVK hash value: ";
    libzeth::field_element_write_json(hash_value, std::cout);
    std::cout << "\n";

    ASSERT_EQ(nvk_hash_value, hash_value);
}

TEST(VerificationKeyHashTest, HashTest)
{
    using wpp = libff::bw6_761_pp;
    verification_key_hash_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>,
        libzeth::BLAKE2s_256<libff::Fr<wpp>>>();
}

TEST(VerificationKeyHashTest, HashGadgetTest)
{
    using wpp = libff::bw6_761_pp;
    verification_key_hash_gadget_test<
        wpp,
        libzecale::groth16_verifier_parameters<wpp>,
        libzeth::BLAKE2s_256<libff::Fr<wpp>>>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::bw6_761_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
