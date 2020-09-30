// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUIT_NULL_GADGET_HPP__
#define __ZECALE_CIRCUIT_NULL_GADGET_HPP__

namespace libzecale
{

template<typename FieldT>
null_hash_gadget<FieldT>::null_hash_gadget(
    libsnark::protoboard<FieldT> & /* pb */,
    const libsnark::block_variable<FieldT> & /* input */,
    const libsnark::digest_variable<FieldT> & /* output */,
    const std::string & /* annotation_prefix */)
{
}

template<typename FieldT>
void null_hash_gadget<FieldT>::generate_r1cs_constraints(
    const bool /* ensure_output_bitness */)
{
}

template<typename FieldT> void null_hash_gadget<FieldT>::generate_r1cs_witness()
{
}

template<typename FieldT> size_t null_hash_gadget<FieldT>::get_digest_len()
{
    return 0;
}

} // namespace libzecale

#endif // __ZECALE_CIRCUIT_NULL_GADGET_HPP__
