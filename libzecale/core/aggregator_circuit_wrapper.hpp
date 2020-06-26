// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__

#include "libzecale/circuits/aggregator.tcc"

#include <libzeth/core/extended_proof.hpp>
#include <libzeth/snarks/default/default_snark.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wSnarkT,
    size_t NumProofs>
class aggregator_circuit_wrapper
{
private:
    std::shared_ptr<aggregator_gadget<nppT, wppT, nSnarkT, NumProofs>>
        aggregator_g;

public:
    aggregator_circuit_wrapper(){};

    typename wSnarkT::KeypairT generate_trusted_setup() const;
    libsnark::protoboard<libff::Fr<wppT>> get_constraint_system() const;

    /// Generate a proof and returns an extended proof
    extended_proof<wppT, wSnarkT> prove(
        typename nSnarkT::VerificationKeyT nested_vk,
        const std::array<
            const libzeth::extended_proof<nppT, nSnarkT> *,
            NumProofs> &extended_proofs,
        const typename wSnarkT::ProvingKeyT &aggregator_proving_key) const;
};

} // namespace libzecale

#include "aggregator_circuit_wrapper.tcc"

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
