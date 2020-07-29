// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_TCC__
#define __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_TCC__

#include "libzecale/tests/circuits/dummy_application.hpp"

namespace libzecale
{

namespace test
{

template<typename ppT>
check_inverse_gadget<ppT>::check_inverse_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &a,
    const libsnark::pb_variable<FieldT> &a_inv,
    const std::string &annotation_index)
    : libsnark::gadget<FieldT>(pb, annotation_index), _a(a), _a_inv(a_inv)
{
}

template<typename ppT>
void check_inverse_gadget<ppT>::generate_r1cs_constraints() const
{
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_a, _a_inv, 1), " a*a_inv==1");
}

template<typename ppT>
void check_inverse_gadget<ppT>::generate_r1cs_witness() const
{
    this->pb.val(_a_inv) = this->pb.val(_a).inverse();
}

} // namespace test

} // namespace libzecale

#endif // __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_TCC__
