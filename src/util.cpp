// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "util.hpp"

namespace libzecale
{

void erase_substring(std::string &string, const std::string &substring)
{
	size_t position = string.find(substring);
 
	if (position != std::string::npos)
	{
		string.erase(position, substring.length());
	}
}

uint8_t* parse_hex_field_element_to_bytes(std::string element)
{
    const char hexstring[] = element.c_str();
    const char* pos = hexstring;

    const size_t length = strlen(hexstring);

    // We assume for now that the string received is of the right form
    // ie.
    // - No "0x" prefix
    // - Valid hexadecimal string
    // - Even length
    //
    // TODO: harden this and handle edge cases
    uint8_t[length/2] bytes;

    // We iterate on the length of bytes
    for (size_t count = 0; count < sizeof(bytes)/sizeof(*bytes); count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    return bytes;
}

} // libzecale