// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__
#define __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__

#include "libzecale/circuits/verification_key_hash_gadget.hpp"

namespace libzecale
{

// verification_key_scalar_hash_gadget

template<typename wppT, typename nverifierT>
verification_key_hash_gadget<wppT, nverifierT>::verification_key_hash_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    verification_key_variable &verification_key,
    libsnark::pb_variable<libff::Fr<wppT>> &verification_key_hash,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _hash_gadget(
          pb,
          verification_key.get_all_vars(),
          verification_key_hash,
          FMT(annotation_prefix, " _hash_gadget"))
{
}

template<typename wppT, typename nverifierT>
void verification_key_hash_gadget<wppT, nverifierT>::generate_r1cs_constraints()
{
    _hash_gadget.generate_r1cs_constraints();
}

template<typename wppT, typename nverifierT>
void verification_key_hash_gadget<wppT, nverifierT>::generate_r1cs_witness()
{
    _hash_gadget.generate_r1cs_witness();
}

template<typename wppT, typename nverifierT>
libff::Fr<wppT> verification_key_hash_gadget<wppT, nverifierT>::compute_hash(
    const typename nsnark::verification_key &vk, size_t num_inputs)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<libff::Fr<wppT>> nvk_hash;
    nvk_hash.allocate(pb, "nvk_hash");
    verification_key_variable nvk(pb, num_inputs, "nvk");
    libzecale::verification_key_hash_gadget<wppT, nverifierT> nvk_hash_gadget(
        pb, nvk, nvk_hash, "nvk_hash_gadget");

    nvk_hash_gadget.generate_r1cs_constraints();

    nvk.generate_r1cs_witness(vk);
    nvk_hash_gadget.generate_r1cs_witness();

    return pb.val(nvk_hash);
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__
