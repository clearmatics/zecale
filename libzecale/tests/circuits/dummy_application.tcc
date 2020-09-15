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
check_multiplicative_inverse_gadget<ppT>::check_multiplicative_inverse_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &a,
    const libsnark::pb_variable<FieldT> &a_inv,
    const std::string &annotation_index)
    : libsnark::gadget<FieldT>(pb, annotation_index), _a(a), _a_inv(a_inv)
{
}

template<typename ppT>
void check_multiplicative_inverse_gadget<ppT>::generate_r1cs_constraints() const
{
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_a, _a_inv, 1), " a*a_inv==1");
}

template<typename ppT>
void check_multiplicative_inverse_gadget<ppT>::generate_r1cs_witness() const
{
    this->pb.val(_a_inv) = this->pb.val(_a).inverse();
}

template<typename ppT, typename snarkT>
dummy_app_wrapper<ppT, snarkT>::dummy_app_wrapper()
    : _pb()
    , _check_inverse(
          _pb,
          libsnark::pb_variable<FieldT>(1),
          libsnark::pb_variable<FieldT>(2),
          "check_inverse")
{
    _a.allocate(_pb, "a");
    _a_inv.allocate(_pb, "a_inv");
    assert(_a.index == _check_inverse._a.index);
    assert(_a_inv.index == _check_inverse._a_inv.index);
    _check_inverse.generate_r1cs_constraints();
    _pb.set_input_sizes(1);
}

template<typename ppT, typename snarkT>
typename snarkT::keypair dummy_app_wrapper<ppT, snarkT>::generate_keypair()
{
    return snarkT::generate_setup(_pb);
}

template<typename ppT, typename snarkT>
typename libzeth::extended_proof<ppT, snarkT> dummy_app_wrapper<ppT, snarkT>::
    prove(size_t scalar, const typename snarkT::proving_key &pk)
{
    FieldT a(scalar);
    _pb.val(_a) = a;
    _check_inverse.generate_r1cs_witness();

    typename snarkT::proof proof = snarkT::generate_proof(_pb, pk);
    libsnark::r1cs_primary_input<FieldT> primary_input = _pb.primary_input();
    return libzeth::extended_proof<ppT, snarkT>(
        std::move(proof), std::move(primary_input));
}

} // namespace test

} // namespace libzecale

#endif // __ZECALE_TESTS_CIRCUITS_DUMMY_APPLICATION_TCC__
