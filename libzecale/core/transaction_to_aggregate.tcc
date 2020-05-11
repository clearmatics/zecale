// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_TCC__
#define __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_TCC__

#include <array>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

template<typename ppT, typename snarkT>
transaction_to_aggregate<ppT, snarkT>::transaction_to_aggregate(
    std::string application_name,
    const libzeth::extended_proof<ppT, snarkT> &extended_proof,
    uint32_t fee_wei)
    : _application_name(application_name), _fee_wei(fee_wei)
{
    this->_extended_proof =
        std::make_shared<libzeth::extended_proof<ppT, snarkT>>(extended_proof);
}

template<typename ppT, typename snarkT>
std::ostream &operator<<(
    std::ostream &os, const transaction_to_aggregate<ppT, snarkT> &tx)
{
    os << "app-name:" << tx.application_name() << ", fee-wei" << tx.fee_wei();
    return os;
}

} // namespace libzecale

#endif // __ZECALE_TYPES_TRANSACTION_TO_AGGREGATE_TCC__