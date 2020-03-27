// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_TCC__
#define __ZECALE_UTIL_TCC__

#include <string>
#include <libff/algebra/fields/bigint.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>

#include "gmp.h"

namespace libzecale
{

template<typename FieldT>
FieldT hex_str_to_field_element(std::string field_str)
{
    // Remove prefix if any
    erase_substring(field_str, std::string("0x"));

    // 1 byte will be populated by 2 hexadecimal characters
    uint8_t val[field_str.size()/2];

    char cstr[field_str.size() + 1];
    strcpy(cstr, field_str.c_str());
    int res = hex_str_to_bin(cstr, val);

    libff::bigint<FieldT::num_limbs> el = libzeth::libsnark_bigint_from_bytes<FieldT>(val);
    return FieldT(el);
}

} // namespace libzecale

#endif // __ZECALE_UTIL_TCC__