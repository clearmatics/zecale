// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
#define __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__

#include "libzecale/core/nested_transaction.hpp"

#include <zecale/api/aggregator.pb.h>

namespace libzecale
{

template<typename nppT, typename wppT, typename nsnarkT, typename wsnarkT>
void aggregator_configuration_to_proto(
    zecale_proto::AggregatorConfiguration &config);

template<typename ppT, typename apiHandlerT>
nested_transaction<ppT, typename apiHandlerT::snark> nested_transaction_from_proto(
    const zecale_proto::NestedTransaction &transaction);

} // namespace libzecale

#include "libzecale/serialization/proto_utils.tcc"

#endif // __ZECALE_SERIALIZATION_PROTO_UTILS_HPP__
