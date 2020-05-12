// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__
#define __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__

#include "libzecale/core/transaction_to_aggregate.hpp"

#include <cstring>
#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libzeth/core/extended_proof.hpp>
#include <libzeth/snarks/default/default_api_handler.hpp>


namespace libzecale
{

template<typename ppT, typename snarkHandlerT>
transaction_to_aggregate<ppT, snarkHandlerT::snarkT> transaction_to_aggregate_from_proto(
    const zecale_proto::TransactionToAggregate &grpc_transaction_obj)
{
    std::string app_name = grpc_transaction_obj.application_name();
    libzeth::extended_proof<ppT, snarkT> ext_proof =
        snarkHandlerT::extended_proof_from_proto<ppT, snarkHandlerT::snarkT>(grpc_transaction_obj.extended_proof());
    uint32_t fee = uint32_t(grpc_transaction_obj.fee_in_wei());

    return transaction_to_aggregate<ppT, snarkHandlerT::snarkT>(app_name, ext_proof, fee);
}

} // namespace libzecale

#endif // __ZECALE_SERIALIZATION_PROTO_UTILS_TCC__