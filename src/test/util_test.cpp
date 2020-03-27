#include "gtest/gtest.h"

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>

#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include "util.hpp"

#include <stdio.h>

typedef libff::mnt4_pp ppT;
typedef libff::Fq<ppT> FieldT;

using namespace libzecale;

namespace
{

TEST(MainTests, SerializationTest)
{
    FieldT element = FieldT::random_element();
    std::string field_str = libzeth::hex_from_libsnark_bigint<FieldT>(element.as_bigint());
    FieldT res = hex_str_to_field_element<FieldT>(field_str);

    ASSERT_EQ(res, element);
    //ASSERT_TRUE(FieldT(el) == element2);

    //FieldT retrieved_element = hex_str_to_field_element<FieldT>(field_str);

    //libff::G1<ppT> g1_point = libff::G1<ppT>::random_element();
    //std::string libzeth::point_g1_affine_as_hex(const libff::G1<ppT> &point);

    //libff::G2<ppT> g2_point = libff::G2<ppT>::random_element();
    //std::string libzeth::point_g2_affine_as_hex(const libff::G2<ppT> &point);
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


/*

TEST(MainTests, SerializationTest)
{
    FieldT element = FieldT::random_element();
    FieldT element2 = FieldT::random_element();
    std::string field_str = libzeth::hex_from_libsnark_bigint<FieldT>(element.as_bigint());
    std::cout << "field_str: " << field_str << std::endl;
    //libff::bigint<FieldT::num_limbs> big = element.as_bigint();
    //std::cout << "print_hex" << std::endl;
    //big.print_hex();

    erase_substring(field_str, std::string("0x"));
    std::cout << "field_str: " << field_str << std::endl;
    //std::string test("DEadbeef10203040b00b1e50");
    //uint8_t val[(FieldT::num_bits + 8 - 1) / 8];
    std::cout << "(FieldT::num_bits + 8 - 1) / 8]: " << (FieldT::num_bits + 8 - 1) / 8 << std::endl;
    std::cout << "field_str.size()/2: " <<  field_str.size()/2 << std::endl;
    uint8_t val[field_str.size()/2];
    char cstr[field_str.size() + 1];
    strcpy(cstr, field_str.c_str());
    int res = hex_str_to_bin(cstr, val);

    std::cout << "here" << std::endl;
    printf("0x");
    for(size_t count = 0; count < sizeof(val)/sizeof(uint8_t); count++)
        printf("%02x", val[count]);
    printf("\n");

    libff::bigint<FieldT::num_limbs> el = libzeth::libsnark_bigint_from_bytes<FieldT>(val);
    el.print_hex();

    ASSERT_TRUE(FieldT(el) == element);
    ASSERT_TRUE(FieldT(el) == element2);

    //FieldT retrieved_element = hex_str_to_field_element<FieldT>(field_str);

    //libff::G1<ppT> g1_point = libff::G1<ppT>::random_element();
    //std::string libzeth::point_g1_affine_as_hex(const libff::G1<ppT> &point);

    //libff::G2<ppT> g2_point = libff::G2<ppT>::random_element();
    //std::string libzeth::point_g2_affine_as_hex(const libff::G2<ppT> &point);
}


*/