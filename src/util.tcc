// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_UTIL_TCC__
#define __ZECALE_UTIL_TCC__

#include "gmp.h"

#include <libff/algebra/fields/bigint.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <string>

#include <libsnark/common/data_structures/accumulation_vector.hpp>

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

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> parse_str_acc_vector(std::string acc_vector_str)
{
    //std::string input_str = "[[one0, one1], [two0, two1], [three0, three1], [four0, four1]]";
    char *cstr = new char[acc_vector_str.length() + 1];
    std::strcpy(cstr, acc_vector_str.c_str());
    char *pos;
    printf("Splitting string \"%s\" into tokens:\n", cstr);

    std::vector<std::string> res;
    pos = strtok(cstr, "[, ]");

    while (pos != NULL) {
        res.push_back(std::string(pos));
        pos = strtok(NULL, "[, ]");
    }

    // Free heap memory allocated with the `new` above
    delete[] cstr;
    
    // Each element of G1 has 2 coordinates (the points are in the affine form)
    //
    // Messy check that the size of the vector resulting from the string parsing is of
    // the form 2*n meaning that it contains the x and y coordinates of n points
    if (res.size() > 0 && res.size() % 2 != 0) {
        // TODO: Do exception throwing/catching properly
        std::cerr << "parse_str_acc_vector: Wrong number of coordinates" << std::endl;
        exit(1);
    }

    libsnark::accumulation_vector<libff::G1<ppT>> acc_res;
    libff::Fq<ppT> x_coordinate = hex_str_to_field_element<libff::Fq<ppT>>(res[0]);
    libff::Fq<ppT> y_coordinate = hex_str_to_field_element<libff::Fq<ppT>>(res[1]);

    libff::G1<ppT> first_point_g1 = libff::G1<ppT>(x_coordinate, y_coordinate);
    acc_res.first = first_point_g1;

    // Set the `rest` of the accumulation vector
    libsnark::sparse_vector<libff::G1<ppT>> rest;
    libff::G1<ppT> point_g1;
    for (size_t i = 2; i < res.size(); i+=2) {
        // TODO:
        // This is BAD => this code is a duplicate of the function `hex_str_to_field_element`
        // Let's re-use the content of the function `hex_str_to_field_element` here.
        // To do this properly this means that we need to modify the type of `abc_g1`
        // in the proto file to be a repeated G1 element (and not a string)
        // Likewise for the inputs which should be changed to repeated field elements
        libff::Fq<ppT> x_coordinate =
            hex_str_to_field_element<libff::Fq<ppT>>(res[i]);
        libff::Fq<ppT> y_coordinate =
            hex_str_to_field_element<libff::Fq<ppT>>(res[i+1]);

        point_g1 = libff::G1<ppT>(x_coordinate, y_coordinate);
        rest[i/2 - 1] = point_g1;
    }

    acc_res.rest = rest;
    return acc_res;
}

} // namespace libzecale

#endif // __ZECALE_UTIL_TCC__