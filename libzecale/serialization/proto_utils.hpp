// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
#define __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__

#include "libzecale/core/transaction_to_aggregate.hpp"

#include <zecale/api/aggregator.pb.h>

namespace libzecale
{

template<typename ppT, typename apiHandlerT>
transaction_to_aggregate<ppT, typename apiHandlerT::snark>
transaction_to_aggregate_from_proto(
    const zecale_proto::TransactionToAggregate &transaction);

} // namespace libzecale

#include "proto_utils.tcc"

#endif // __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
