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

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
aggregator_circuit_wrapper<nppT, wppT, nsnarkT, wverifierT, NumProofs>::
    aggregator_circuit_wrapper(const size_t inputs_per_nested_proof)
    : _num_inputs_per_nested_proof(inputs_per_nested_proof)
    , _pb()
    , _aggregator_gadget(_pb, _num_inputs_per_nested_proof)
{
    _aggregator_gadget.generate_r1cs_constraints();
}

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
typename wverifierT::snark::keypair aggregator_circuit_wrapper<
    nppT,
    wppT,
    nsnarkT,
    wverifierT,
    NumProofs>::generate_trusted_setup() const
{
    // Generate a verification and proving key (trusted setup)
    return wsnark::generate_setup(_pb);
}

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
const libsnark::protoboard<libff::Fr<wppT>>
    &aggregator_circuit_wrapper<nppT, wppT, nsnarkT, wverifierT, NumProofs>::
        get_constraint_system() const
{
    return _pb;
}

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
libzeth::extended_proof<wppT, typename wverifierT::snark> aggregator_circuit_wrapper<
    nppT,
    wppT,
    nsnarkT,
    wverifierT,
    NumProofs>::
    prove(
        const typename nsnarkT::verification_key &nested_vk,
        const std::array<
            const libzeth::extended_proof<nppT, nsnarkT> *,
            NumProofs> &extended_proofs,
        const typename wsnark::proving_key &aggregator_proving_key)
{
    for (const libzeth::extended_proof<nppT, nsnarkT> *ep : extended_proofs) {
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
    return extended_proof<wppT, wsnark>(
        wsnark::generate_proof(_pb, aggregator_proving_key),
        _pb.primary_input());
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
