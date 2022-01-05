// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_VERIFICATION_KEY_HASH_GADGET_HPP__
#define __ZECALE_CIRCUITS_VERIFICATION_KEY_HASH_GADGET_HPP__

#include "libzecale/circuits/compression_function_selector.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libzeth/circuits/mimc/mimc_input_hasher.hpp>

namespace libzecale
{

/// Gadget to produce the hash of a verification key for nested proofs. Relies
/// on a hash gadget `hashT` which operates directly on arrays of scalars,
/// producing digests which are also scalars.
template<typename wppT, typename nverifierT>
class verification_key_hash_gadget : public libsnark::gadget<libff::Fr<wppT>>
{
public:
    using FieldT = libff::Fr<wppT>;
    using compFnT = compression_function_gadget<wppT>;
    using scalarHasherT = libzeth::mimc_input_hasher<FieldT, compFnT>;

    using nsnark = typename nverifierT::snark;
    using verification_key_variable =
        typename nverifierT::verification_key_variable_gadget;

    /// Gadget to hash vk bits.
    scalarHasherT _hash_gadget;

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
