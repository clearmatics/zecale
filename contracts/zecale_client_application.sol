// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

/// Interface that must be implemented by any client applications of Zecale.
contract ZecaleClientApplication
{
    /// The main entry-point called by Zecale. Implementations should ensure
    /// that this is called by a trusted implementation of the Zecale
    /// dispatcher.
    ///
    /// `nested_vk_hash` - the hash of the nested verification key.
    /// Implementations should check that this is correct.
    ///
    /// `nested_inputs` - the inputs to the nested proof.
    ///
    /// `nested_parameters` - other parameters (not included in the nested
    /// proof inputs) to be passed as part of this invocation.
    function dispatch(
        uint256 nested_vk_hash,
        uint256[] memory nested_inputs,
        uint256[] memory nested_parameters) public payable;
}
