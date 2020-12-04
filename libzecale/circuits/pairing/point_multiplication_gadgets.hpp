// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+
#ifndef __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__

#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>

namespace libzecale
{

/// Utility function to get the value from a (witnessed) G1_variable.
template<typename wppT>
libff::G1<other_curve<wppT>> g1_variable_get_element(
    const libsnark::G1_variable<wppT> &g1_variable);

/// Utility function to get the value from a (witnessed) G2_variable.
template<typename wppT>
libff::G2<other_curve<wppT>> g2_variable_get_element(
    const libsnark::G2_variable<wppT> &var);

} // namespace libzecale

#include "libzecale/circuits/pairing/point_multiplication_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__
