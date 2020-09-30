// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__
#define __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

namespace test
{

/// Trivial gadget to check multiplicative inverse in the field. For inputs a
/// and a_inv, generates a single constraint that a * a_inv == 1.
template<typename ppT>
class check_multiplicative_inverse_gadget : libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;

    libsnark::pb_variable<FieldT> _a;
    libsnark::pb_variable<FieldT> _a_inv;

    check_multiplicative_inverse_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &a,
        const libsnark::pb_variable<FieldT> &a_inv,
        const std::string &annotation_index);
    void generate_r1cs_constraints() const;
    void generate_r1cs_witness() const;
};

template<typename ppT, typename snarkT> class dummy_app_wrapper
{
public:
    using FieldT = libff::Fr<ppT>;
    static const size_t num_primary_inputs = 1;

    libsnark::protoboard<FieldT> _pb;
    libsnark::pb_variable<FieldT> _a;
    libsnark::pb_variable<FieldT> _a_inv;
    check_multiplicative_inverse_gadget<ppT> _check_inverse;

    dummy_app_wrapper();
    typename snarkT::keypair generate_keypair();
    typename libzeth::extended_proof<ppT, snarkT> prove(
        size_t scalar, const typename snarkT::proving_key &vk);
};

} // namespace test

} // namespace libzecale

#include "libzecale/tests/circuits/dummy_application.tcc"

#endif // __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__
