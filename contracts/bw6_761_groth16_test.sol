// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./bw6_761_groth16.sol";

contract bw6_761_groth16_test
{
    uint256[] _vk;

    function test_verify(
        uint256[] memory vk,
        uint256[18] memory proof,
        uint256[] memory inputs) public returns(bool)
    {
        // Copy vk into storage
        _vk = vk;

        // Call verify
        return bw6_761_groth16.verify(_vk, proof, inputs);
    }
}
