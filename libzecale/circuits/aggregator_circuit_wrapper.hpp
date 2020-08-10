// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__

#include "libzecale/circuits/aggregator_gadget.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libzeth/core/extended_proof.hpp>

using namespace libzeth;

namespace libzecale
{

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
class aggregator_circuit_wrapper
{
private:
    using npp = other_curve<wppT>;
    using nsnark = typename nverifierT::snark;

    const size_t _num_inputs_per_nested_proof;

    libsnark::protoboard<libff::Fr<wppT>> _pb;
    aggregator_gadget<wppT, nverifierT, NumProofs> _aggregator_gadget;

public:
    explicit aggregator_circuit_wrapper(const size_t inputs_per_nested_proof);

    typename wsnarkT::keypair generate_trusted_setup() const;

    const libsnark::protoboard<libff::Fr<wppT>> &get_constraint_system() const;

    /// Generate a proof and returns an extended proof
    extended_proof<wppT, wsnarkT> prove(
        const typename nsnark::verification_key &nested_vk,
        const std::array<
            const libzeth::extended_proof<npp, nsnark> *,
            NumProofs> &extended_proofs,
        const typename wsnarkT::proving_key &aggregator_proving_key);
};

} // namespace libzecale

#include "aggregator_circuit_wrapper.tcc"

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
