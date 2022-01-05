// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./Groth16BW6_761.sol";

contract Groth16BW6_761_test
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
        return Groth16BW6_761.verify(_vk, proof, inputs);
    }
}
