// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./bw6_761_groth16.sol";

contract bw6_761_groth16_test
{
    // TODO: Pass vk and proof as single arrays

    function test_verify(
        uint256[6] memory alpha,
        uint256[6] memory beta,
        uint256[6] memory delta,
        uint256[] memory abc,
        uint256[6] memory a,
        uint256[6] memory b,
        uint256[6] memory c,
        uint256[] memory inputs) public returns(bool)
    {
        return 0 != bw6_761_groth16.verify(alpha, beta, delta, abc, a, b, c, inputs);
    }
}
