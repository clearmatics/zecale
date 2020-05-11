// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__
#define __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__

#include <array>
#include <libzeth/libsnark_helpers/extended_proof.hpp>

namespace libzecale
{

/// This class represents the type of transactions that are aggregated using
/// zecale. The application name is used to determine which verification key
/// needs to be used to verify the proof in the transaction.
template<typename ppT> class transaction_to_aggregate
{
private:
    std::string _application_name;
    std::shared_ptr<libzeth::extended_proof<ppT>> _extended_proof;
    uint32_t _fee_wei;
    // size_t identifier; // to switch to something better like a hash

public:
    transaction_to_aggregate(){};
    transaction_to_aggregate(
        std::string application_name,
        const libzeth::extended_proof<ppT> &extended_proof,
        uint32_t fee_wei = 0);
    virtual ~transaction_to_aggregate(){};

    inline std::string application_name() const
    {
        return this->_application_name;
    };
    inline libzeth::extended_proof<ppT> extended_proof() const
    {
        return *(this->_extended_proof);
    };
    inline uint32_t fee_wei() const { return this->_fee_wei; };

    // Overload the less-than operator in order to compare objects in priority
    // queue
    bool operator<(const transaction_to_aggregate &right) const;
};

template<typename ppT>
bool transaction_to_aggregate<ppT>::operator<(
    const transaction_to_aggregate<ppT> &right) const
{
    return _fee_wei < right._fee_wei;
}

template<typename ppT>
std::ostream &operator<<(
    std::ostream &os, const transaction_to_aggregate<ppT> &tx);

} // namespace libzecale

#include "transaction_to_aggregate.tcc"

#endif // __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__