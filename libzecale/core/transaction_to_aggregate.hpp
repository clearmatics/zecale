// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__
#define __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__

#include <array>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

/// This class represents the type of transactions that are aggregated using
/// zecale. The application name is used to determine which verification key
/// needs to be used to verify the proof in the transaction.
template<typename nppT, typename nsnarkT> class transaction_to_aggregate
{
private:
    std::string _application_name;
    std::shared_ptr<libzeth::extended_proof<nppT, nsnarkT>> _extended_proof;
    uint32_t _fee_wei;
    // TODO: switch to something better like a hash
    // size_t identifier;

public:
    transaction_to_aggregate(){};
    transaction_to_aggregate(
        const std::string &application_name,
        const libzeth::extended_proof<nppT, nsnarkT> &extended_proof,
        uint32_t fee_wei = 0);
    virtual ~transaction_to_aggregate(){};

    inline const std::string &application_name() const
    {
        return this->_application_name;
    };

    inline const libzeth::extended_proof<nppT, nsnarkT> &extended_proof() const
    {
        return *(this->_extended_proof);
    };

    inline uint32_t fee_wei() const { return this->_fee_wei; };

    std::ostream &write_json(std::ostream &) const;

    /// Overload the less-than operator in order to compare objects in priority
    /// queue
    bool operator<(const transaction_to_aggregate<nppT, nsnarkT> &right) const;
};

} // namespace libzecale

#include "transaction_to_aggregate.tcc"

#endif // __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_HPP__
