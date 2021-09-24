// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_HPP__
#define __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_HPP__

#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>

namespace libzecale
{

/// Version of libsnark::r1cs_ppzksnark_verification_key_variable that exposes
/// the scalar variables (equivalent of
/// r1cs_gg_ppzksnark_verification_key_scalar_variable). We are forced to
/// inherit from libsnark::r1cs_ppzksnark_verification_key_variable in order
/// that this object can be passed to the
/// libsnark::r1cs_ppzksnark_verifier_gadget, hence this version is not optimal
/// (the bit variables are all still allocated). An optimal version would
/// require larger changes in libsnark.
template<typename ppT>
class r1cs_ppzksnark_verification_key_scalar_variable
    : public libsnark::r1cs_ppzksnark_verification_key_variable<ppT>
{
public:
    using FieldT = libff::Fr<ppT>;

    r1cs_ppzksnark_verification_key_scalar_variable(
        libsnark::protoboard<FieldT> &pb,
        const size_t input_size,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    size_t num_primary_inputs() const;
    const libsnark::pb_linear_combination_array<FieldT> &get_all_vars() const;
    static std::vector<FieldT> get_verification_key_scalars(
        const libsnark::r1cs_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &r1cs_vk);

private:
    static libsnark::pb_variable_array<FieldT> allocate_all_bits(
        libsnark::protoboard<FieldT> &pb,
        const size_t input_size,
        const std::string &annotation_prefix);
};

} // namespace libzecale

#include "libzecale/circuits/pghr13_verifier/r1cs_ppzksnark_verification_key_scalar_variable.tcc"

#endif // __ZECALE_CIRCUITS_PGHR13_VERIFIER_R1CS_PPZKSNARK_VERIFICATION_KEY_SCALAR_VARIABLE_HPP__
