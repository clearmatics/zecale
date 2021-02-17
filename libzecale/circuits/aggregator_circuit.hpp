// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_HPP__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_HPP__

#include "libzecale/circuits/aggregator_gadget.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"
#include "libzecale/circuits/verification_key_hash_gadget.hpp"

#include <libzeth/core/extended_proof.hpp>

using namespace libzeth;

namespace libzecale
{

/// Creates a circuit for creating a wrapping proof aggregating a batch of
/// nested proofs. Inputs are allocated as follows:
///
///   <hash of nested verification key>
///   <packed_results>
///   <nested_inputs[1]>
///   <nested_inputs[2]>
///   ...
///   <nested_inputs[N]>
///
/// where:
///   N = NumProofs,
///   packed_results = verification result for all proofs, represented as bits
///   nested_inputs[i][j] = j-th input to i-th proof,
template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
class aggregator_circuit
{
private:
    using npp = other_curve<wppT>;
    using nsnark = typename nverifierT::snark;
    using verification_key_variable_gadget =
        typename nverifierT::verification_key_scalar_variable_gadget;
    using proof_variable_gadget = typename nverifierT::proof_variable_gadget;

    const size_t _num_inputs_per_nested_proof;

    libsnark::protoboard<libff::Fr<wppT>> _pb;

    /// (Primary) Variable holding the hash of the verification key for nested
    /// proofs. Verified against the actual verification key values, by the
    /// _nested_vk_hash_gadget.
    libsnark::pb_variable<libff::Fr<wppT>> _nested_vk_hash;

    /// (Primary) Results of the verifiers as bits. 1 meaning that the nested
    /// proof is valid, 0 meaning it may not be valid. (LO-bit corresponds to
    /// 0-th nested proof).
    libsnark::pb_variable<libff::Fr<wppT>> _nested_proof_results;

    /// (Primary) The nested primary inputs lie in the scalar field
    /// `libff::Fr<nppT>`, and must be represented as elements of
    /// `libff::Fr<wppT>` for use in the wrapper proof.
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        _nested_primary_inputs;

    /// (Auxiliary) The array of the results of the verifiers, as scalars.
    std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
        _nested_proof_results_unpacked;

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

    /// Gadget to check the hash of the nested verification key.
    std::shared_ptr<verification_key_scalar_hash_gadget<wppT, nverifierT>>
        _nested_vk_hash_gadget;

    /// Gadget to aggregate proofs.
    std::shared_ptr<aggregator_gadget<wppT, nverifierT, NumProofs>>
        _aggregator_gadget;

    /// Nested proof verification results packer
    std::shared_ptr<libsnark::packing_gadget<libff::Fr<wppT>>>
        _nested_proof_results_packer;

public:
    explicit aggregator_circuit(const size_t inputs_per_nested_proof);

    aggregator_circuit(const aggregator_circuit &other) = delete;
    const aggregator_circuit &operator=(const aggregator_circuit &other) =
        delete;

    typename wsnarkT::keypair generate_trusted_setup() const;

    // Number of primary inputs to the wrapping circuit
    size_t num_primary_inputs() const;

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

#include "aggregator_circuit.tcc"

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_HPP__
