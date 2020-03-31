#include "util.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <stdio.h>

typedef libff::mnt4_pp ppT;
// typedef libff::Fq<ppT> FieldT;

using namespace libzecale;

namespace
{

TEST(MainTests, ParseFieldElement)
{
    // 1. Format and parse field element
    libff::Fq<ppT> element_base = libff::Fq<ppT>::random_element();
    std::string field_str_base =
        libzeth::hex_from_libsnark_bigint<libff::Fq<ppT>>(
            element_base.as_bigint());
    libff::Fq<ppT> res_base =
        hex_str_to_field_element<libff::Fq<ppT>>(field_str_base);

    // DEBUG
    std::cout << "element_base: " << std::endl;
    element_base.as_bigint().print_hex();
    std::cout << "res_base: " << std::endl;
    res_base.as_bigint().print_hex();

    ASSERT_EQ(res_base, element_base);

    libff::Fr<ppT> element_scalar = libff::Fr<ppT>::random_element();
    std::string field_str_scalar =
        libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(
            element_scalar.as_bigint());
    libff::Fr<ppT> res_scalar =
        hex_str_to_field_element<libff::Fr<ppT>>(field_str_scalar);

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
    // see:
    // https://github.com/clearmatics/zeth/blob/develop/src/snarks/groth16/api/response.tcc#L30-L41
    // additional `\"` are added there. Remove these in Zeth as this is
    // unecessary.
    //
    // Moreover, let's write a "util" function to format primary inputs and use
    // the function in:
    // - Here:
    // https://github.com/clearmatics/zeth/blob/develop/src/snarks/groth16/api/response.tcc#L30-L41,
    // and
    // - Here:
    // https://github.com/clearmatics/zeth/blob/develop/src/snarks/pghr13/api/response.tcc#L46-L56
    //
    // See: https://github.com/clearmatics/zeth/pull/183
    // TODO: Use the function `format_primary_inputs` defined in the PR above
    // when it is merged, and when the submodules are updated
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
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}