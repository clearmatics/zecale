// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_APPLICATION_POOL_HPP__
#define __ZECALE_CORE_APPLICATION_POOL_HPP__

#include "transaction_to_aggregate.hpp"

#include <queue>

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
    const std::string _name;

    /// Verification key used to verify the nested proofs
    const typename nsnarkT::verification_key _verification_key;

    /// Pool of transactions to aggregate
    std::priority_queue<transaction_to_aggregate<nppT, nsnarkT>> _tx_pool;

public:
    application_pool(
        const std::string &name, const typename nsnarkT::verification_key &vk);

    // Prevent some operations which may have unintended consequences and
    // unnecessary allocation and copying.

    application_pool(const application_pool &other) = delete;
    application_pool &operator=(const application_pool &other) = delete;

    const std::string &name() const;

    /// Function that returns the verification key associated with this
    /// application. This constitutes part of the witness of the aggregator
    /// circuit.
    const typename nsnarkT::verification_key &verification_key() const;

    /// Add transaction to the pool
    void add_tx(const transaction_to_aggregate<nppT, nsnarkT> &tx);

    /// Returns the number of transactions in the _tx_pool
    size_t tx_pool_size() const;

    // TODO: Use better types to make it safer to retrieve smaller batches.

    /// Fill the array with transactions popped from the queue. Returns the
    /// number of transactions placed in the array. Any remaining entries are
    /// unntouched, and should be ignored by the caller.
    size_t get_next_batch(
        std::array<transaction_to_aggregate<nppT, nsnarkT>, NumProofs> &batch);
};

} // namespace libzecale

#include "application_pool.tcc"

#endif // __ZECALE_CORE_APPLICATION_POOL_HPP__
