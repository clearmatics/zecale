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
    using verification_key_variable_gadget =
        typename nverifierT::verification_key_variable_gadget;
    using proof_variable_gadget = typename nverifierT::proof_variable_gadget;

    const size_t _num_inputs_per_nested_proof;

    libsnark::protoboard<libff::Fr<wppT>> _pb;

    /// (Primary) The nested primary inputs lie in the scalar field
    /// `libff::Fr<nppT>`, and must be represented as elements of
    /// `libff::Fr<wppT>` for use in the wrapper proof.
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        _nested_primary_inputs;

    /// (Primary) The array of the results of the verifiers. 1 meaning that the
    /// nested proof is valid, 0 meaning it may not be valid.
    std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
        _nested_proof_results;

    /// (Auxiliary) Verification key used to verify the nested proofs. Consists
    /// of group elements of `nppT`, which again, can be represented using
    /// elements in `libff::Fr<wppT>`.
    std::shared_ptr<verification_key_variable_gadget> _nested_vk;

    /// (Auxiliary) The nested proofs (defined over `nppT`) to verify. As above,
    /// these are verified by virtue of the fact that the base field for nppT is
    /// the scalar field of wppT. These gadgets handle take a witness in the
    /// form of a proof with group elements from nppT and represent them as
    /// variables in the wppT scalar field.
    /// (Variables are expected to be auxiliary inputs).
    std::array<std::shared_ptr<proof_variable_gadget>, NumProofs>
        _nested_proofs;

    std::shared_ptr<aggregator_gadget<wppT, nverifierT, NumProofs>>
        _aggregator_gadget;

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
