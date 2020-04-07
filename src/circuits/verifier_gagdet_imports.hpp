// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_VERIFIER_CIRCUIS_ALIAS_HPP__
#define __ZECALE_VERIFIER_CIRCUIS_ALIAS_HPP__

// ------------------------- Pick a zkSNARK -------------------------

#ifdef ZKSNARK_PGHR13
#define LIBZECALE_VERIFIER_GADGET_DEFINED
#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>
namespace libzecale
{
template<typename ppT>
using verifierGadgetT = libsnark::r1cs_ppzksnark_verifier_gadget<ppT>;
template<typename ppT>
using proofVariableGadgetT = libsnark::r1cs_ppzksnark_proof_variable<ppT>;
template<typename ppT>
using verificationKeyVariableGadgetT =
    libsnark::r1cs_ppzksnark_verification_key_variable<ppT>;
} // namespace libzecale
#endif

#ifdef ZKSNARK_GROTH16
#define LIBZECALE_VERIFIER_GADGET_DEFINED
#include "src/circuits/groth16_verifier/r1cs_gg_ppzksnark_verifier_gagdet.hpp"
namespace libzecale
{
template<typename ppT>
using verifierGadgetT = r1cs_gg_ppzksnark_verifier_gadget<ppT>;
template<typename ppT>
using proofVariableGadgetT = r1cs_gg_ppzksnark_proof_variable<ppT>;
template<typename ppT>
using verificationKeyVariableGadgetT =
    r1cs_gg_ppzksnark_verification_key_variable<ppT>;
} // namespace libzecale
#endif

#ifndef LIBZECALE_VERIFIER_GADGET_DEFINED
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZECALE_VERIFIER_CIRCUIS_ALIAS_HPP__