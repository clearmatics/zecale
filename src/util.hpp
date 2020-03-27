// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_TCC__
#define __ZECALE_UTIL_TCC__

#include <string>

namespace libzecale
{

void erase_substring(std::string &string, const std::string &substring);
uint8_t* parse_hex_field_element_to_bytes(std::string element);

} // namespace libzecale