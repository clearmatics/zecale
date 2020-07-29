// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__
#define __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>

namespace libzecale
{

namespace test
{

/// Trivial gadget to check multiplicative inverse in the field. For inputs a
/// and a_inv, generates a single constraint that a * a_inv == 1.
template<typename ppT>
class check_inverse_gadget : libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;

    libsnark::pb_variable<FieldT> _a;
    libsnark::pb_variable<FieldT> _a_inv;

    check_inverse_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &a,
        const libsnark::pb_variable<FieldT> &a_inv,
        const std::string &annotation_index);
    void generate_r1cs_constraints() const;
    void generate_r1cs_witness() const;
};

} // namespace test

} // namespace libzecale

#include "libzecale/tests/circuits/dummy_application.tcc"

#endif // __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_HPP__
