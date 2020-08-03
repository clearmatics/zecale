// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

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
    : num_inputs_per_nested_proof(inputs_per_nested_proof)
{
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
    libsnark::protoboard<libff::Fr<wppT>> pb;
    aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs> g(
        pb, num_inputs_per_nested_proof);
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup)
    typename wsnark::keypair keypair = wsnark::generate_setup(pb);

    return keypair;
}

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
libsnark::protoboard<libff::Fr<wppT>> aggregator_circuit_wrapper<
    nppT,
    wppT,
    nsnarkT,
    wverifierT,
    NumProofs>::get_constraint_system() const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;
    aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs> g(
        pb, num_inputs_per_nested_proof);
    g.generate_r1cs_constraints();
    return pb;
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
        const typename wsnark::proving_key &aggregator_proving_key) const
{
    for (const libzeth::extended_proof<nppT, nsnarkT> *ep : extended_proofs) {
        if (ep->get_primary_inputs().size() != num_inputs_per_nested_proof) {
            throw std::runtime_error(
                "attempt to aggregate proof with invalid number of inputs");
        }
    }

    libsnark::protoboard<libff::Fr<wppT>> pb;

    aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs> g(
        pb, num_inputs_per_nested_proof);
    g.generate_r1cs_constraints();
    // We pass to the witness generation function the elements defined over the
    // "other curve". See:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    g.generate_r1cs_witness(nested_vk, extended_proofs);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness
              << " ***" << std::endl;

    typename wsnark::proof proof =
        wsnark::generate_proof(pb, aggregator_proving_key);
    libsnark::r1cs_primary_input<libff::Fr<wppT>> primary_input =
        pb.primary_input();

    // Instantiate an extended_proof from the proof we generated and the
    // given primary_input
    libzeth::extended_proof<wppT, wsnark> ext_proof =
        extended_proof<wppT, wsnark>(
            std::move(proof), std::move(primary_input));

    return ext_proof;
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
