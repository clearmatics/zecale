// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_API_HPP__
#define __ZECALE_UTIL_API_HPP__

#include "api/util.pb.h"

#include "types/transaction_to_aggregate.hpp"

namespace libzecale
{

template<typename ppT>
transaction_to_aggregate<ppT> parse_transaction_to_aggregate(const aggregator_proto::TransactionToAggregate &transaction);

template<typename ppT>
aggregator_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point);

template<typename ppT>
aggregator_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point);

} // namespace libzecale
#include "util_api.tcc"

#endif // __ZECALE_UTIL_API_HPP__