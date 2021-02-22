// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_GROTH16_VERIFIER_GROTH16_VERIFIER_PARAMETERS_HPP__
#define __ZECALE_CIRCUITS_GROTH16_VERIFIER_GROTH16_VERIFIER_PARAMETERS_HPP__

#include "libzecale/circuits/groth16_verifier/r1cs_gg_ppzksnark_verifier_gadget.hpp"

#include <libzeth/snarks/groth16/groth16_snark.hpp>

namespace libzecale
{

/// Type definitions to use the groth16 verifier circuit.
template<typename ppT> class groth16_verifier_parameters
{
public:
    using snark = libzeth::groth16_snark<other_curve<ppT>>;

    using process_verification_key_gadget =
        r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>;
    using online_verifier_gadget =
        r1cs_gg_ppzksnark_online_verifier_gadget<ppT>;
    using verifier_gadget = r1cs_gg_ppzksnark_verifier_gadget<ppT>;

    using proof_variable_gadget = r1cs_gg_ppzksnark_proof_variable<ppT>;
    using verification_key_variable_gadget =
        r1cs_gg_ppzksnark_verification_key_variable<ppT>;
    using verification_key_scalar_variable_gadget =
        r1cs_gg_ppzksnark_verification_key_scalar_variable<ppT>;
    using processed_verification_key_variable_gadget =
        r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
            ppT>;
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_GROTH16_VERIFIER_GROTH16_VERIFIER_PARAMETERS_HPP__
