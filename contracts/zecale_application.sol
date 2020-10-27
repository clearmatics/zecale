// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

interface IZecaleApplication {
    function dispatch(
        uint256 vk_hash,
        uint256[] memory inputs,
        uint256[] memory parameters) public payable;
}