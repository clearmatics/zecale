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

int hex_str_to_bin(char *source_str, uint8_t *dest_buffer)
{
  char *line = source_str;
  char *data = line;
  int offset;
  int read_byte;
  int data_len = 0;

  while (sscanf(data, "%02x%n", &read_byte, &offset) == 1) {
    dest_buffer[data_len++] = read_byte;
    data += offset;
  }
  return data_len;
}

} // libzecale