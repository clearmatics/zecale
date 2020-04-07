// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_TCC__
#define __ZECALE_UTIL_TCC__

#include "gmp.h"

#include <libff/algebra/fields/bigint.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <string>

namespace libzecale
{

template<typename FieldT> FieldT hex_str_to_field_element(std::string field_str)
{
    // Remove prefix if any
    erase_substring(field_str, std::string("0x"));

    // 1 byte will be populated by 2 hexadecimal characters
    uint8_t val[field_str.size() / 2];

    char cstr[field_str.size() + 1];
    strcpy(cstr, field_str.c_str());

    int res = hex_str_to_bin(cstr, val);
    if (res == 0) {
        // TODO: Do exception throwing/catching properly
        std::cerr << "hex_str_to_bin: No data converted" << std::endl;
        exit(1);
    }

    libff::bigint<FieldT::num_limbs> el =
        libzeth::libsnark_bigint_from_bytes<FieldT>(val);
    return FieldT(el);
}

template<typename ppT>
std::vector<libff::Fr<ppT>> parse_str_inputs(std::string input_str)
{
    char *cstr = new char[input_str.length() + 1];
    std::strcpy(cstr, input_str.c_str());
    char *pos;
    printf("Splitting string \"%s\" into tokens:\n", cstr);

    std::vector<libff::Fr<ppT>> res;
    pos = strtok(cstr, "[, ]");

    while (pos != NULL) {
        res.push_back(
            hex_str_to_field_element<libff::Fr<ppT>>(std::string(pos)));
        pos = strtok(NULL, "[, ]");
    }

    // Free heap memory allocated with the `new` above
    delete[] cstr;

    return res;
}

} // namespace libzecale

#endif // __ZECALE_UTIL_TCC__