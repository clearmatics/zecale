// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

#include "libzecale/circuits/aggregator_circuit_wrapper.hpp"

#include <libzeth/zeth_constants.hpp>

using namespace libzeth;

namespace libzecale
{

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
aggregator_circuit_wrapper<wppT, wsnarkT, nverifierT, NumProofs>::
    aggregator_circuit_wrapper(const size_t inputs_per_nested_proof)
    : _num_inputs_per_nested_proof(inputs_per_nested_proof)
    , _pb()
    , _aggregator_gadget(_pb, _num_inputs_per_nested_proof)
{
    _aggregator_gadget.generate_r1cs_constraints();
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
typename wsnarkT::keypair aggregator_circuit_wrapper<
    wppT,
    wsnarkT,
    nverifierT,
    NumProofs>::generate_trusted_setup() const
{
    // Generate a verification and proving key (trusted setup)
    return wsnarkT::generate_setup(_pb);
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
const libsnark::protoboard<libff::Fr<wppT>>
    &aggregator_circuit_wrapper<wppT, wsnarkT, nverifierT, NumProofs>::
        get_constraint_system() const
{
    return _pb;
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
libzeth::extended_proof<wppT, wsnarkT> aggregator_circuit_wrapper<
    wppT,
    wsnarkT,
    nverifierT,
    NumProofs>::
    prove(
        const typename nsnark::verification_key &nested_vk,
        const std::array<
            const libzeth::extended_proof<npp, nsnark> *,
            NumProofs> &extended_proofs,
        const typename wsnarkT::proving_key &aggregator_proving_key)
{
    for (const libzeth::extended_proof<npp, nsnark> *ep : extended_proofs) {
        if (ep->get_primary_inputs().size() != _num_inputs_per_nested_proof) {
            throw std::runtime_error(
                "attempt to aggregate proof with invalid number of inputs");
        }
    }

    // We pass to the witness generation function the elements defined over the
    // "other curve". See:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    _aggregator_gadget.generate_r1cs_witness(nested_vk, extended_proofs);

    bool is_valid_witness = _pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness
              << " ***" << std::endl;

    // Return an extended_proof for the given witness.
    return extended_proof<wppT, wsnarkT>(
        wsnarkT::generate_proof(_pb, aggregator_proving_key),
        _pb.primary_input());
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
