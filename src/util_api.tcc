// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_API_TCC__
#define __ZECALE_UTIL_API_TCC__

#include "util.hpp"
#include "util_api.hpp"
#include "types/transaction_to_aggregate.hpp"

namespace libzecale
{

template<typename ppT>
transaction_to_aggregate<ppT> parse_transaction_to_aggregate(
    const aggregator_proto::TransactionToAggregate &transaction)
{
    std::string app_name = transaction.application_name());
    libzeth::extended_proof<ppT> ext_proof = parse_extended_proof(transaction.extended)
    uint32_t fee = uint32_t(transaction.fee_in_wei());

    return transaction_to_aggregate<ppT>(
        app_name,
        ext_proof,
        fee);
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_extended_proof(
    const aggregator_proto::ExtendedProof &ext_proof)
{
#ifdef ZKSNARK_PGHR13
    return parse_pghr13_extended_proof(ext_proof);
#elif ZKSNARK_GROTH16
    return parse_groth16_extended_proof(ext_proof);
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif
}

// TODO:
// Think about supporting point compression to minimize bandwidth usage
// but this needs to be "tradeoffed" with the decompression work given to
// the aggregator.
template<typename ppT>
libff::G1<ppT> parse_hexPointBaseGroup1Affine(
    const aggregator_proto::HexPointBaseGroup1Affine &point)
{
    libff::Fq<ppT> x_coordinate = hex_str_to_field_element(point.x_coord());
    libff::Fq<ppT> y_coordinate = hex_str_to_field_element(point.y_coord());

    libff::G1<ppT> libff_point = libff::G1<ppT>(x_coordinate, y_coordinate);

    return res;
}

template<typename ppT>
libff::G2<ppT> parse_hexPointBaseGroup2Affine(
    const aggregator_proto::HexPointBaseGroup1Affine &point)
{
    libff::Fq<ppT> x_c1 = hex_str_to_field_element(point.x_c1_coord());
    libff::Fq<ppT> x_c0 = hex_str_to_field_element(point.x_c0_coord());
    libff::Fq<ppT> y_c1 = hex_str_to_field_element(point.y_c1_coord());
    libff::Fq<ppT> y_c0 = hex_str_to_field_element(point.y_c0_coord());

    libff::Fqe<ppT> x_coordinate(x_c0, x_c1);
    libff::Fqe<ppT> y_coordinate(y_c0, y_c1);

    libff::G2<ppT> libff_point = libff::G2<ppT>(x_coordinate, y_coordinate, libff::Fqe<ppT>::one());

    return res;
}

template<typename ppT>
aggregator_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point)
{
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.as_bigint());
    std::string y_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.as_bigint());

    aggregator_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(x_coord);
    res.set_y_coord(y_coord);

    return res;
}

template<typename ppT>
aggregator_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point)
{
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c1.as_bigint());
    std::string x_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c0.as_bigint());
    std::string y_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c1.as_bigint());
    std::string y_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c0.as_bigint());

    aggregator_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord(x_c0_coord);
    res.set_x_c1_coord(x_c1_coord);
    res.set_y_c0_coord(y_c0_coord);
    res.set_y_c1_coord(y_c1_coord);

    return res;
}

} // namespace libzecale

#endif // __ZECALE_UTIL_API_TCC__
