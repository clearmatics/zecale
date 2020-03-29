// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_APPLICATION_POOL_HPP__
#define __ZECALE_APPLICATION_POOL_HPP__

#include <queue>
#include <vector>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "transaction_to_aggregate.hpp"

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
    std::string _name;

    std::shared_ptr<libsnark::r1cs_ppzksnark_verification_key<ppT>> _verification_key;
    // For now we just use a basic FIFO structure to consume the proofs
    // However, we can be more sophisticated and define an ordering policy
    // to order the proofs received and consume them.
    //
    // TODO: Switch to a pool with an "order_by" policy
    // something like std::priority_queue for eg.
    std::priority_queue<transaction_to_aggregate<ppT>, std::vector<transaction_to_aggregate<ppT>>> _tx_pool;

public:
    application_pool(std::string name, libsnark::r1cs_ppzksnark_verification_key<ppT> vk);
    virtual ~application_pool(){};

    inline std::string name() const { return this->_name; };

    // Function that returns the verification key associated with this application.
    // This constitutes part of the witness of the aggregator circuit.
    inline libsnark::r1cs_ppzksnark_verification_key<ppT> verification_key() const { return *(this->_verification_key); };

    // Function that returns the next batch of proofs to aggregate.
    // This constitutes part of the witness of the aggregator circuit.
    //
    // TODO: Harden this function to pad the batch with dummy inputs if there are less
    // proofs in the queue than the batch size.
    std::array<transaction_to_aggregate<ppT>, NumProofs> get_next_batch();

    // Returns the number of transactions in the _tx_pool
    inline size_t tx_pool_size() { return this->_tx_pool.size(); }

    // Add transaction to the pool
    inline void add_tx(transaction_to_aggregate<ppT> tx) { this->_tx_pool.push(tx); return; }
};

} // namespace libzecale
#include "application_pool.tcc"

#endif // __ZECALE_APPLICATION_POOL_HPP__