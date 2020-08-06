// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__

#include "libzecale/circuits/aggregator_gadget.hpp"

#include <libzeth/core/extended_proof.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
class aggregator_circuit_wrapper
{
private:
    using wsnark = typename wverifierT::snark;

    const size_t _num_inputs_per_nested_proof;

    libsnark::protoboard<libff::Fr<wppT>> _pb;
    aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs>
        _aggregator_gadget;

public:
    explicit aggregator_circuit_wrapper(const size_t inputs_per_nested_proof);

    typename wsnark::keypair generate_trusted_setup() const;

    const libsnark::protoboard<libff::Fr<wppT>> &get_constraint_system() const;

    /// Generate a proof and returns an extended proof
    extended_proof<wppT, wsnark> prove(
        const typename nsnarkT::verification_key &nested_vk,
        const std::array<
            const libzeth::extended_proof<nppT, nsnarkT> *,
            NumProofs> &extended_proofs,
        const typename wsnark::proving_key &aggregator_proving_key);
};

} // namespace libzecale

#include "aggregator_circuit_wrapper.tcc"

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
