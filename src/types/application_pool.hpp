// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_APPLICATION_POOL_HPP__
#define __ZECALE_APPLICATION_POOL_HPP__

#include <queue>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libzeth/libsnark_helpers/extended_proof.hpp>

namespace libzecale
{

/// An `application_pool` represents the pool of proofs to be aggregated that
/// are for the same predicate.
///
/// For example, we can have an `application_pool` to aggregate `Zeth` proofs
/// and an other `aggregation_pool` to aggregate proofs for other type
/// of statements.
template<
    typename ppT,
    size_t NumProofs>
class application_pool
{
private:
    // Name/Identifier of the application (E.g. "zeth")
    std::string name;

    std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<ppT>> verification_key;
    // For now we just use a basic FIFO structure to consume the proofs
    // However, we can be more sophisticated and define an ordering policy
    // to order the proofs received and consume them.
    //
    // TODO: Switch to a pool with an "order_by" policy
    // something like std::priority_queue for eg.
    std::queue<std::shared_ptr<libzeth::extended_proof<ppT>>> proofs_queue; // Modify this to be a pool of transactions to aggregate and order the pool per the fee (which was added as a field in the proto files)

public:
    application_pool(std::string name, libsnark::r1cs_ppzksnark_verification_key<ppT> vk);

    // Function that returns the next batch of proofs to aggregate.
    // This constitutes part of the witness of the aggregator circuit.
    //
    // TODO: Harden this function to pad the batch with dummy inputs if there are less
    // proofs in the queue than the batch size.
    std::array<libzeth::extended_proof<ppT>, NumProofs> get_next_batch();

    // Function that returns the verification key associated with this application.
    // This constitutes part of the witness of the aggregator circuit.
    libsnark::r1cs_ppzksnark_verification_key<ppT> get_verification_key();
};

} // namespace libzecale
#include "application_pool.tcc"

#endif // __ZECALE_APPLICATION_POOL_HPP__