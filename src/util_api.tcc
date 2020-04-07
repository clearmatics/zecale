// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_API_TCC__
#define __ZECALE_UTIL_API_TCC__

#include "types/transaction_to_aggregate.hpp"
#include "util.hpp"
#include "util_api.hpp"

#include <cstring>
#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libzeth/libsnark_helpers/extended_proof.hpp>

// Support only for PGHR13 for now
// template<typename ppT> using proofT = libsnark::r1cs_ppzksnark_proof<ppT>;

namespace libzecale
{

/// Format points using affine coordinates
template<typename ppT>
aggregator_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point)
{
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.as_bigint());
    std::string y_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.as_bigint());

    aggregator_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(x_coord);
    res.set_y_coord(y_coord);

    return res;
}

/// Format points using affine coordinates
template<typename ppT>
aggregator_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point)
{
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_c1_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c1.as_bigint());
    std::string x_c0_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c0.as_bigint());
    std::string y_c1_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c1.as_bigint());
    std::string y_c0_coord =
        "0x" +
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c0.as_bigint());

    aggregator_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord(x_c0_coord);
    res.set_x_c1_coord(x_c1_coord);
    res.set_y_c0_coord(y_c0_coord);
    res.set_y_c1_coord(y_c1_coord);

    return res;
}

// TODO:
// Think about supporting point compression to minimize bandwidth usage
// but this needs to be "tradeoffed" with the decompression work given to
// the aggregator.

/// Parse points in affine coordinates
template<typename ppT>
libff::G1<ppT> parse_hexPointBaseGroup1Affine(
    const aggregator_proto::HexPointBaseGroup1Affine &point)
{
    libff::Fq<ppT> x_coordinate =
        hex_str_to_field_element<libff::Fq<ppT>>(point.x_coord());
    libff::Fq<ppT> y_coordinate =
        hex_str_to_field_element<libff::Fq<ppT>>(point.y_coord());

    libff::G1<ppT> res = libff::G1<ppT>(x_coordinate, y_coordinate);

    return res;
}

/// Parse points in affine coordinates
template<typename ppT>
libff::G2<ppT> parse_hexPointBaseGroup2Affine(
    const aggregator_proto::HexPointBaseGroup2Affine &point)
{
    libff::Fq<ppT> x_c1 =
        hex_str_to_field_element<libff::Fq<ppT>>(point.x_c1_coord());
    libff::Fq<ppT> x_c0 =
        hex_str_to_field_element<libff::Fq<ppT>>(point.x_c0_coord());
    libff::Fq<ppT> y_c1 =
        hex_str_to_field_element<libff::Fq<ppT>>(point.y_c1_coord());
    libff::Fq<ppT> y_c0 =
        hex_str_to_field_element<libff::Fq<ppT>>(point.y_c0_coord());

    // See:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/public_params.hpp#L88
    // and:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp#L33
    //
    // As such, each element of Fqe is assumed to be a vector of 2 coefficients
    // lying in the base field
    libff::Fqe<ppT> x_coordinate(x_c0, x_c1);
    libff::Fqe<ppT> y_coordinate(y_c0, y_c1);

    libff::G2<ppT> res =
        libff::G2<ppT>(x_coordinate, y_coordinate, libff::Fqe<ppT>::one());

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_groth16_extended_proof(
    const aggregator_proto::ExtendedProof &ext_proof)
{
    const aggregator_proto::ExtendedProofGROTH16 &e_proof =
        ext_proof.groth16_extended_proof();
    // G1
    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    // G2
    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    // G1
    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());

    std::vector<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_inputs<ppT>(e_proof.inputs()));

    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        std::move(a), std::move(b), std::move(c));
    libzeth::extended_proof<ppT> res(proof, inputs);

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_pghr13_extended_proof(
    const aggregator_proto::ExtendedProof &ext_proof)
{
    const aggregator_proto::ExtendedProofPGHR13 &e_proof =
        ext_proof.pghr13_extended_proof();

    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    libff::G1<ppT> a_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_A(a, a_p);

    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    libff::G1<ppT> b_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.b_p());
    libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>> g_B(b, b_p);

    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());
    libff::G1<ppT> c_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_C(c, c_p);

    libff::G1<ppT> h = parse_hexPointBaseGroup1Affine<ppT>(e_proof.h());
    libff::G1<ppT> k = parse_hexPointBaseGroup1Affine<ppT>(e_proof.k());

    libsnark::r1cs_ppzksnark_proof<ppT> proof(
        std::move(g_A),
        std::move(g_B),
        std::move(g_C),
        std::move(h),
        std::move(k));
    libsnark::r1cs_primary_input<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_inputs<ppT>(e_proof.inputs()));
    libzeth::extended_proof<ppT> res(proof, inputs);

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_extended_proof(
    const aggregator_proto::ExtendedProof &ext_proof)
{
#ifdef ZKSNARK_PGHR13
    return parse_pghr13_extended_proof<ppT>(ext_proof);
#elif ZKSNARK_GROTH16
    return parse_groth16_extended_proof<ppT>(ext_proof);
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif
}

template<typename ppT>
transaction_to_aggregate<ppT> parse_transaction_to_aggregate(
    const aggregator_proto::TransactionToAggregate &grpc_transaction_obj)
{
    std::string app_name = grpc_transaction_obj.application_name();
    libzeth::extended_proof<ppT> ext_proof =
        parse_extended_proof<ppT>(grpc_transaction_obj.extended_proof());
    uint32_t fee = uint32_t(grpc_transaction_obj.fee_in_wei());

    return transaction_to_aggregate<ppT>(app_name, ext_proof, fee);
}

} // namespace libzecale

#endif // __ZECALE_UTIL_API_TCC__
