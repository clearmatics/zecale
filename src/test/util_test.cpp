#include "gtest/gtest.h"

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>

#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include "util.hpp"

#include <stdio.h>

typedef libff::mnt4_pp ppT;
//typedef libff::Fq<ppT> FieldT;

using namespace libzecale;

namespace
{

TEST(MainTests, ParseFieldElement)
{
    // 1. Format and parse field element
    libff::Fq<ppT> element_base = libff::Fq<ppT>::random_element();
    std::string field_str_base = libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(element_base.as_bigint());
    libff::Fq<ppT> res_base = hex_str_to_field_element<libff::Fq<ppT>>(field_str_base);

    // DEBUG
    std::cout << "element_base: " << std::endl;
    element_base.as_bigint().print_hex();
    std::cout << "res_base: " << std::endl;
    res_base.as_bigint().print_hex();

    ASSERT_EQ(res_base, element_base);

    libff::Fr<ppT> element_scalar = libff::Fr<ppT>::random_element();
    std::string field_str_scalar = libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(element_scalar.as_bigint());
    libff::Fr<ppT> res_scalar = hex_str_to_field_element<libff::Fr<ppT>>(field_str_scalar);

    // DEBUG
    std::cout << "element_scalar: " << std::endl;
    element_scalar.as_bigint().print_hex();
    std::cout << "res_scalar: " << std::endl;
    res_scalar.as_bigint().print_hex();

    ASSERT_EQ(res_scalar, element_scalar);
}

TEST(MainTests, ParsePublicInputs)
{
    // Format and parse public inputs
    std::vector<libff::Fr<ppT>> public_inputs;
    public_inputs.push_back(libff::Fr<ppT>::random_element());
    public_inputs.push_back(libff::Fr<ppT>::random_element());
    public_inputs.push_back(libff::Fr<ppT>::random_element());

    // 1. Format public inputs
    // Let's be consistent with the formatting functions of Zeth
    // see: https://github.com/clearmatics/zeth/blob/develop/src/snarks/groth16/api/response.tcc#L30-L41
    // additional `\"` are added there. Remove these in Zeth as this is unecessary.
    //
    // Moreover, let's write a "util" function to format primary inputs and use the function in:
    // - Here: https://github.com/clearmatics/zeth/blob/develop/src/snarks/groth16/api/response.tcc#L30-L41, and
    // - Here: https://github.com/clearmatics/zeth/blob/develop/src/snarks/pghr13/api/response.tcc#L46-L56
    //
    // See: https://github.com/clearmatics/zeth/pull/183
    // TODO: Use the function `format_primary_inputs` defined in the PR above when it is merged, and when the submodules are updated
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "0x"
           << libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(
                  public_inputs[i].as_bigint());
        if (i < public_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json_str = ss.str();

    // 2. Parse the inputs
    std::vector<libff::Fr<ppT>> res = parse_str_inputs<ppT>(inputs_json_str);
    ASSERT_EQ(res, public_inputs);

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