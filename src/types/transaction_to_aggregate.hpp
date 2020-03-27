// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__
#define __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__

#include <array>
#include <libzeth/libsnark_helpers/extended_proof.hpp>

namespace libzecale
{

/// This class represents the type of transactions that are aggregated using zecale.
/// The application name is used to determine which verification key needs to be used to verify
/// the proof in the transaction.
template<typename ppT>
class transaction_to_aggregate
{
private:
    std::string application_name;
    std::shared_ptr<libzeth::extended_proof<ppT>> extended_proof;
    uint32_t fee_wei;

public:
    transaction_to_aggregate(std::string application_name, const libzeth::extended_proof<ppT> &extended_proof, uint32_t fee_wei = 0);
    virtual ~transaction_to_aggregate(){};

    inline std::string application_name() const { return this->application_name; };
    inline libzeth::extended_proof<ppT> extended_proof() const { return *(this->extended_proof); };
    inline uint32_t fee_wei() const { return this->fee_wei; };
};

} // namespace libzecale
#include "transaction_to_aggregate.tcc"

#endif // __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__