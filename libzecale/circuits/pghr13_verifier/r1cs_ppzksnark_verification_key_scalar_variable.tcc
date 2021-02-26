// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_TCC__
#define __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_TCC__

#include "libzecale/circuits/pghr13_verifier/r1cs_ppzksnark_verification_key_scalar_variable.hpp"

namespace libzecale
{

template<typename ppT>
r1cs_ppzksnark_verification_key_scalar_variable<ppT>::
    r1cs_ppzksnark_verification_key_scalar_variable(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const size_t input_size,
        const std::string &annotation_prefix)
    : libsnark::r1cs_ppzksnark_verification_key_variable<ppT>(
          pb,
          allocate_all_bits(pb, input_size, annotation_prefix),
          input_size,
          annotation_prefix)
{
}

template<typename ppT>
void r1cs_ppzksnark_verification_key_scalar_variable<
    ppT>::generate_r1cs_constraints()
{
    libsnark::r1cs_ppzksnark_verification_key_variable<
        ppT>::generate_r1cs_constraints(false);
}

template<typename ppT>
size_t r1cs_ppzksnark_verification_key_scalar_variable<
    ppT>::num_primary_inputs() const
{
    return libsnark::r1cs_ppzksnark_verification_key_variable<ppT>::input_size;
}

template<typename ppT>
const libsnark::pb_linear_combination_array<libff::Fr<ppT>>
    &r1cs_ppzksnark_verification_key_scalar_variable<ppT>::get_all_vars() const
{
    return libsnark::r1cs_ppzksnark_verification_key_variable<ppT>::all_vars;
}

template<typename ppT>
std::vector<libff::Fr<ppT>> r1cs_ppzksnark_verification_key_scalar_variable<
    ppT>::
    get_verification_key_scalars(
        const libsnark::r1cs_ppzksnark_verification_key<other_curve<ppT>>
            &r1cs_vk)
{
    const size_t input_size_in_elts =
        r1cs_vk.encoded_IC_query.rest.indices
            .size(); // this might be approximate for bound verification
    // keys, however they are not supported by
    // r1cs_ppzksnark_verification_key_variable
    const size_t vk_size_in_bits =
        libsnark::r1cs_ppzksnark_verification_key_variable<ppT>::size_in_bits(
            input_size_in_elts);

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable_array<FieldT> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");
    r1cs_ppzksnark_verification_key_scalar_variable<ppT> vk(
        pb, vk_bits, input_size_in_elts, "translation_step_vk");
    vk.generate_r1cs_witness(r1cs_vk);

    const size_t num_scalars = vk.all_vars.size();
    std::vector<FieldT> scalars;
    scalars.reserve(num_scalars);
    for (size_t i = 0; i < num_scalars; ++i) {
        scalars.push_back(pb.lc_val(vk.all_vars[i]));
    }

    return scalars;
}

template<typename ppT>
libsnark::pb_variable_array<libff::Fr<ppT>>
r1cs_ppzksnark_verification_key_scalar_variable<ppT>::allocate_all_bits(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const size_t input_size,
    const std::string &annotation_prefix)
{
    libsnark::pb_variable_array<FieldT> arr;
    arr.allocate(
        pb,
        libsnark::r1cs_ppzksnark_verification_key_variable<ppT>::size_in_bits(
            input_size),
        FMT(annotation_prefix, " vk_bits"));
    return arr;
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_TCC__
