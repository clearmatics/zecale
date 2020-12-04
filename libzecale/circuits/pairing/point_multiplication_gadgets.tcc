// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__
#define __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__

#include "libzecale/circuits/pairing/point_multiplication_gadgets.hpp"

namespace libzecale
{

namespace implementation
{

// Internal class used to extract the value of a G1_variable.
template<typename wppT>
class G1_variable_with_get_element : public libsnark::G1_variable<wppT>
{
public:
    using nppT = other_curve<wppT>;
    inline libff::G1<nppT> get_element() const
    {
        return libff::G1<nppT>(
            this->pb.lc_val(this->X),
            this->pb.lc_val(this->Y),
            libff::Fq<nppT>::one());
    }
};

} // namespace implementation

template<typename wppT>
libff::G1<other_curve<wppT>> g1_variable_get_element(
    const libsnark::G1_variable<wppT> &var)
{
    return ((implementation::G1_variable_with_get_element<wppT> *)(&var))
        ->get_element();
}

template<typename wppT>
libff::G2<other_curve<wppT>> g2_variable_get_element(
    const libsnark::G2_variable<wppT> &var)
{
    using nppT = other_curve<wppT>;
    return libff::G2<nppT>(
        var.X->get_element(),
        var.Y->get_element(),
        libff::G2<nppT>::twist_field::one());
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__
