// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_HPP__
#define __ZECALE_UTIL_HPP__

#include <string>
#include <string.h>

namespace libzecale
{

void erase_substring(std::string &string, const std::string &substring);
int hex_str_to_bin(char *source_str, uint8_t *dest_buffer);

template<typename FieldT>
FieldT hex_str_to_field_element(std::string field_str);

} // namespace libzecale
#include "util.tcc"

#endif // __ZECALE_UTIL_HPP__