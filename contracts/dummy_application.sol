// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./zecale_client_application.sol";

// Trivial dummy application used to test the Zecale protocol. Transactions
// demonstrate knowledge of the multiplicative inverse of scalar value. The
// contract state records the set of scalars seen so far, rejecting
// transactions for scalars that have already been seen.
contract DummyApplication is ZecaleClientApplication
{
    // The address of the single contract trusted to call dispatch endpoint.
    address _permitted_dispatcher;

    // Hash of nested verification key for proofs associated with this
    // contract.
    uint256 _vk_hash;

    // The set of scalars seen by the contract.
    mapping(uint256 => bool) _scalars;

    constructor(
        address permitted_dispatcher,
        uint256 vk_hash) public
    {
        _permitted_dispatcher = permitted_dispatcher;
        _vk_hash = vk_hash;
    }

    // Implementation of ZecaleClientApplication.dispatch. Here, the single
    // input is the scalar for which knowledge of the multiplicative inverse
    // is demonstrated. `parameters` is currently unused.
    //
    // TODO: require meaningful data in `parameters` and check its correctness.
    function dispatch(
        uint256 vk_hash,
        uint256[] memory inputs,
        uint256[] memory parameters)
        public payable
    {
        // Sanity checks
        require(inputs.length == 1, "unexpeected nested_inputs length");
        require(parameters.length == 0, "unexpected nested_parameters length");

        // Ensure that the caller and vk_hash are as expected
        require(msg.sender == _permitted_dispatcher, "dispatcher not permitted");
        require(vk_hash == _vk_hash, "invalid vk_hash");

        require(!_scalars[inputs[0]], "scalar already seen");
        _scalars[inputs[0]] = true;
    }

    function get(uint256 scalar) public returns (bool)
    {
        return _scalars[scalar];
    }
}
