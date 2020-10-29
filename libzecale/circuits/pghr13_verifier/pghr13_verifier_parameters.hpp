// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PGHR13_VERIFIER_PGHR13_VERIFIER_PARAMETERS_HPP__
#define __ZECALE_CIRCUITS_PGHR13_VERIFIER_PGHR13_VERIFIER_PARAMETERS_HPP__

#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>
#include <libzeth/snarks/pghr13/pghr13_snark.hpp>

namespace libzecale
{

template<typename ppT> class pghr13_verifier_parameters
{
public:
    using snark = libzeth::pghr13_snark<other_curve<ppT>>;

    using verifier_gadget = libsnark::r1cs_ppzksnark_verifier_gadget<ppT>;
    using proof_variable_gadget = libsnark::r1cs_ppzksnark_proof_variable<ppT>;
    using verification_key_variable_gadget =
        libsnark::r1cs_ppzksnark_verification_key_variable<ppT>;
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PGHR13_VERIFIER_PGHR13_VERIFIER_PARAMETERS_HPP__
