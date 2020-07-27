// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_APPLICATION_POOL_HPP__
#define __ZECALE_CORE_APPLICATION_POOL_HPP__

#include "transaction_to_aggregate.hpp"

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <queue>
#include <vector>

namespace libzecale
{

/// An `application_pool` represents the pool of proofs to be aggregated that
/// are for the same predicate.
///
/// For example, we can have an `application_pool` to aggregate `Zeth` proofs
/// and an other `aggregation_pool` to aggregate proofs for other type
/// of statements.
template<typename nppT, typename nsnarkT, size_t NumProofs>
class application_pool
{
private:
    /// Name/Identifier of the application (E.g. "zeth")
    std::string _name;
    /// Verification key used to verify the nested proofs
    std::shared_ptr<typename nsnarkT::verification_key> _verification_key;
    /// Pool of transactions to aggregate
    std::priority_queue<
        transaction_to_aggregate<nppT, nsnarkT>,
        std::vector<transaction_to_aggregate<nppT, nsnarkT>>>
        _tx_pool;

public:
    application_pool() = default;
    application_pool(std::string name, typename nsnarkT::verification_key vk);
    virtual ~application_pool(){};

    inline std::string name() const { return this->_name; };

    /// Function that returns the verification key associated with this
    /// application. This constitutes part of the witness of the aggregator
    /// circuit.
    inline typename nsnarkT::verification_key verification_key() const
    {
        return *(this->_verification_key);
    };

    /// Function that returns the next batch of proofs to aggregate.
    /// This constitutes part of the witness of the aggregator circuit.
    ///
    /// TODO: Harden this function to pad the batch with dummy inputs if there
    /// are less proofs in the queue than the batch size.
    std::array<transaction_to_aggregate<nppT, nsnarkT>, NumProofs> get_next_batch();

    /// Returns the number of transactions in the _tx_pool
    inline size_t tx_pool_size() { return this->_tx_pool.size(); }

    /// Add transaction to the pool
    inline void add_tx(transaction_to_aggregate<nppT, nsnarkT> tx)
    {
        this->_tx_pool.push(tx);
        return;
    }
};

} // namespace libzecale

#include "application_pool.tcc"

#endif // __ZECALE_CORE_APPLICATION_POOL_HPP__
