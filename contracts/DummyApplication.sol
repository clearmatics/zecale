// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./IZecaleApplication.sol";

// Trivial dummy application used to test the Zecale protocol. Transactions
// demonstrate knowledge of the multiplicative inverse of scalar value. The
// contract state records the set of scalars seen so far, rejecting
// transactions for scalars that have already been seen.
contract DummyApplication is IZecaleApplication
{
    // The address of the single contract trusted to call dispatch endpoint.
    address _permitted_dispatcher;

    // Hash of nested verification key for proofs associated with this
    // contract.
    uint256[2] _vk_hash;

    // The set of scalars seen by the contract.
    mapping(uint256 => uint256) _scalars;

    constructor(address permitted_dispatcher, uint256[2] memory vk_hash) public
    {
        _permitted_dispatcher = permitted_dispatcher;
        _vk_hash = vk_hash;
    }

    // Implementation of IZecaleApplication. Here, the single input is the
    // scalar for which knowledge of the multiplicative inverse is
    // demonstrated. `parameters` is the encoding of a dynamically sized array
    // of uint256s, which must have length 1.
    function dispatch(
        uint256[2] memory vk_hash,
        uint256[] memory inputs,
        bytes memory parameters
    )
        public
        payable
        override
    {
        // Decode parameters into the app-specific format.
        uint256[] memory param_uints = abi.decode(parameters, (uint256[]));

        // Sanity checks
        require(inputs.length == 1, "unexpected inputs length");
        require(param_uints.length == 1, "unexpected parameters length");

        // Ensure that the caller and vk_hash are as expected
        require(msg.sender == _permitted_dispatcher, "dispatcher not permitted");
        require(
            vk_hash[0] == _vk_hash[0] && vk_hash[1] == _vk_hash[1],
            "invalid vk_hash");
        require(0 == _scalars[inputs[0]], "scalar already seen");

        require(0 != param_uints[0], "param should not be 0");

        _scalars[inputs[0]] = param_uints[0];
    }

    function get(uint256 scalar) public view returns(uint256)
    {
        return _scalars[scalar];
    }
}
