// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
#define __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__

#include "libzecale/core/nested_transaction.hpp"

#include <zecale/api/aggregator.pb.h>

namespace libzecale
{

template<typename ppT, typename apiHandlerT>
nested_transaction<ppT, typename apiHandlerT::snark> nested_transaction_from_proto(
    const zecale_proto::NestedTransaction &transaction);

} // namespace libzecale

#include "proto_utils.tcc"

#endif // __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
