// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_BITS_TCC__
#define __ZETH_TYPES_BITS_TCC__

#include "bits.hpp"

namespace libzeth
{

template<size_t TreeDepth>
bits_addr<TreeDepth> get_bits_addr_from_vector(const std::vector<bool> &vect)
{
    return dump_vector_in_array<TreeDepth>(vect);
}

/// dump_vector_in_array dumps a vector into an array
template<size_t Size>
std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect)
{
    std::array<bool, Size> array;
    if (vect.size() != Size) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be equal "
            "to the size of the vector)");
    }

    std::copy(vect.begin(), vect.end(), array.begin());
    return array;
};

/// dump_array_in_vector dumps an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr)
{
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

template<size_t TreeDepth>
std::vector<bool> get_vector_from_bits_addr(const bits_addr<TreeDepth> &arr)
{
    return dump_array_in_vector<TreeDepth>(arr);
}

/// binary_addition sums 2 binary strings with or without carry depending on the
/// boolean value of the `with_carry` variable
template<size_t BitLen>
std::array<bool, BitLen> binary_addition(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B, bool with_carry)
{
    std::array<bool, BitLen> sum;
    sum.fill(0);

    bool carry = 0;
    for (int i = BitLen - 1; i >= 0; i--) {
        sum[i] = ((A[i] ^ B[i]) ^ carry);
        carry = ((A[i] & B[i]) | (A[i] & carry)) | (B[i] & carry);
    }

    // If we ask for the last carry to be taken into account (with_carry=true)
    // and that the last carry is 1, then we raise an overflow error
    if (with_carry && carry) {
        throw std::overflow_error("Overflow: The sum of the binary addition "
                                  "cannot be encoded on <BitLen> bits");
    }

    return sum;
}

/// binary_xor computes the XOR of 2 binary strings
template<size_t BitLen>
std::array<bool, BitLen> binary_xor(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B)
{
    std::array<bool, BitLen> xor_array;
    xor_array.fill(0);

    for (int i = BitLen - 1; i >= 0; i--) {
        xor_array[i] = A[i] != B[i];
    }

    return xor_array;
}

} // namespace libzeth

#endif // __ZETH_TYPES_BITS_TCC__
