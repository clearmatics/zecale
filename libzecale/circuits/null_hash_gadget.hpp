// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUIT_NULL_HASH_GADGET_HPP__
#define __ZECALE_CIRCUIT_NULL_HASH_GADGET_HPP__

namespace libzecale
{

/// A trivial hash gadget that can be used as a parameter to the
/// aggregator_circuit to disable verification key hashing during
/// development.
template<typename FieldT> class null_hash_gadget
{
public:
    null_hash_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::block_variable<FieldT> &input,
        const libsnark::digest_variable<FieldT> &output,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints(const bool ensure_output_bitness = true);
    void generate_r1cs_witness();

    static size_t get_digest_len();
};

} // namespace libzecale

#include "libzecale/circuits/null_hash_gadget.tcc"

#endif // __ZECALE_CIRCUIT_NULL_HASH_GADGET_HPP__
