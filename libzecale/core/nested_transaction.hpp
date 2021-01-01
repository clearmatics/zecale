// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_NESTED_TRANSACTION_HPP__
#define __ZECALE_CORE_NESTED_TRANSACTION_HPP__

#include <array>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

/// This class represents transactions to be aggregated using zecale. The
/// application name is used to determine which verification key needs to be
/// used to verify the proof in the transaction.
template<typename nppT, typename nsnarkT> class nested_transaction
{
private:
    std::string _application_name;
    std::shared_ptr<libzeth::extended_proof<nppT, nsnarkT>> _extended_proof;
    std::vector<uint8_t> _parameters;
    uint32_t _fee_wei;

public:
    // TODO: explicitly delete this to remove the possibility of undefined
    // object.
    nested_transaction();

    // TODO: support move semantics for application_name, parameters and
    // extended_proof.
    nested_transaction(
        const std::string &application_name,
        const libzeth::extended_proof<nppT, nsnarkT> &extended_proof,
        const std::vector<uint8_t> &parameters,
        uint32_t fee_wei = 0);

    const std::string &application_name() const;

    const libzeth::extended_proof<nppT, nsnarkT> &extended_proof() const;

    const std::vector<uint8_t> &parameters() const;

    uint32_t fee_wei() const;

    std::ostream &write_json(std::ostream &) const;

    /// Overload the less-than operator in order to compare objects in priority
    /// queue
    bool operator<(const nested_transaction<nppT, nsnarkT> &right) const;
};

} // namespace libzecale

#include "nested_transaction.tcc"

#endif // __ZECALE_CORE_NESTED_TRANSACTION_HPP__
