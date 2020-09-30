// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__
#define __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__

#include "libzecale/circuits/verification_key_hash_gadget.hpp"

namespace libzecale
{

template<typename wppT, typename nverifierT, typename hashT>
verification_key_hash_gadget<wppT, nverifierT, hashT>::
    verification_key_hash_gadget(
        libsnark::protoboard<FieldT> &pb,
        verification_key_variable &verification_key,
        libsnark::pb_variable<FieldT> &verification_key_hash,
        const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _vk_block(
          pb, {verification_key.all_bits}, FMT(annotation_prefix, " _vk_block"))
    , _vk_digest(
          pb, hashT::get_digest_len(), FMT(annotation_prefix, " _vk_digest"))
    , _hash_gadget(
          pb, _vk_block, _vk_digest, FMT(annotation_prefix, " _hash_gadget"))
    , _hash_packer(
          pb,
          _vk_digest.bits,
          verification_key_hash,
          FMT(annotation_prefix, " _vk_hash_packer"))
{
}

template<typename wppT, typename nverifierT, typename hashT>
void verification_key_hash_gadget<wppT, nverifierT, hashT>::
    generate_r1cs_constraints()
{
    _hash_gadget.generate_r1cs_constraints();
    _vk_digest.generate_r1cs_constraints();
    _hash_packer.generate_r1cs_constraints(false);
}

template<typename wppT, typename nverifierT, typename hashT>
void verification_key_hash_gadget<wppT, nverifierT, hashT>::
    generate_r1cs_witness()
{
    _hash_gadget.generate_r1cs_witness();
    _hash_packer.generate_r1cs_witness_from_bits();
}

template<typename wppT, typename nverifierT, typename hashT>
libff::Fr<wppT> verification_key_hash_gadget<wppT, nverifierT, hashT>::
    compute_hash(const typename nsnark::verification_key &vk, size_t num_inputs)
{
    const size_t num_bits =
        nverifierT::verification_key_variable_gadget::size_in_bits(num_inputs);

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<libff::Fr<wppT>> nvk_hash;
    nvk_hash.allocate(pb, "nvk_hash");
    libsnark::pb_variable_array<FieldT> nvk_bits;
    nvk_bits.allocate(pb, num_bits, "nvk_bits");
    typename nverifierT::verification_key_variable_gadget nvk(
        pb, nvk_bits, num_inputs, "nvk");
    libzecale::verification_key_hash_gadget<wppT, nverifierT, hashT>
        nvk_hash_gadget(pb, nvk, nvk_hash, "nvk_hash_gadget");
    nvk.generate_r1cs_constraints(false);
    nvk_hash_gadget.generate_r1cs_constraints();
    nvk.generate_r1cs_witness(vk);
    nvk_hash_gadget.generate_r1cs_witness();
    return pb.val(nvk_hash);
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_VERIFICAION_KEY_HASH_GADGET_TCC__
