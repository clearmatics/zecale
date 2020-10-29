// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_VERIFICATION_KEY_HASH_GADGET_HPP__
#define __ZECALE_CIRCUITS_VERIFICATION_KEY_HASH_GADGET_HPP__

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

namespace libzecale
{

/// Gadget to produce the hash of a verification key for nested proofs. As with
/// generic hash gadgets, the boolean-ness of the input bits is not checked.
/// This should be performed by the verification_key_variable_gadget object.
///
/// Note that the hash is produced from the concatenation of the unpadded bit
/// strings of the key elements. Therefore, there is no guarantee that the
/// input to the hash will be a whole number of bytes and threfore it may be
/// non-trivial to reproduce the hash on other platforms. A static function is
/// provided here to perform that computation.
template<typename wppT, typename nverifierT, typename hashT>
class verification_key_hash_gadget : public libsnark::gadget<libff::Fr<wppT>>
{
public:
    using FieldT = libff::Fr<wppT>;
    using nsnark = typename nverifierT::snark;
    using verification_key_variable =
        typename nverifierT::verification_key_variable_gadget;

    /// Holder for the vk bits as input to the hash
    libsnark::block_variable<FieldT> _vk_block;

    /// Holder for output bits
    libsnark::digest_variable<FieldT> _vk_digest;

    /// Gadget to hash vk bits.
    hashT _hash_gadget;

    /// Packer gadget to pack the output from _hash_gadget into a single field
    /// element.
    libsnark::packing_gadget<FieldT> _hash_packer;

    verification_key_hash_gadget(
        libsnark::protoboard<FieldT> &pb,
        verification_key_variable &verifcation_key,
        libsnark::pb_variable<FieldT> &verification_key_hash,
        const std::string &annotation);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    // TODO: should not require the second parameter, but there is no generic
    // method to extract the number of inputs from the verification key.
    static FieldT compute_hash(
        const typename nsnark::verification_key &vk, size_t num_inputs);
};

} // namespace libzecale

#include "libzecale/circuits/verification_key_hash_gadget.tcc"

#endif // __ZECALE_CIRCUITS_VERIFICATION_KEY_HASH_GADGET_HPP__
