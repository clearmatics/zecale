// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__
#define __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__

#include "libzecale/core/nested_transaction.hpp"

#include <cstring>
#include <libff/algebra/curves/public_params.hpp>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

template<typename ppT, typename apiHandlerT>
nested_transaction<ppT, typename apiHandlerT::snark> nested_transaction_from_proto(
    const zecale_proto::NestedTransaction &grpc_transaction_obj)
{
    using snark = typename apiHandlerT::snark;
    std::string app_name = grpc_transaction_obj.application_name();
    libzeth::extended_proof<ppT, snark> ext_proof =
        apiHandlerT::extended_proof_from_proto(
            grpc_transaction_obj.extended_proof());
    const std::string &parameters_str(grpc_transaction_obj.parameters());
    std::vector<uint8_t> parameters(
        (const uint8_t *)(parameters_str.data()),
        (const uint8_t *)(parameters_str.data() + parameters_str.size()));

    const uint32_t fee = uint32_t(grpc_transaction_obj.fee_in_wei());
    return nested_transaction<ppT, snark>(app_name, ext_proof, parameters, fee);
}

} // namespace libzecale

#endif // __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__
