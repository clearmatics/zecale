// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./bw6_761_groth16.sol";
import "./zecale_application.sol";

// Scalar Conversion
// -----------------
//
// Wrapped proof inputs are scalars in the BW6-761 pairing (377 bits, encoded
// as 2 uint256s). Inputs to nested proofs are scalars of the BLS12-377
// pairing (each of which is 253 bits encoded as a single uint256).
//
// For now, inputs are passed into the contract as full double-words BW6-761
// scalars, and then converted to single-word BLS12-377 scalars before being
// passed to the client application entry point.
//
// TODO: We can potentially save some gas by passing all wrapped inputs
// (potentially including the vk hash) as single-word scalars and expanding
// during verification.

contract ZecaleDispatcher
{
    uint256 constant batch_size = 2;

    // Verification key
    uint256[] _vk;

    // Constructor for Zecale contract. Initializes the batch verification key.
    // `vk` is passed as the verification key encoded as uint256 array, in the
    // format described bw6_761_groth16.sol.
    constructor(uint256[] memory vk) public
    {
        _vk = vk;
    }

    // Event logger to aid contract debugging. Can be removed eventually when
    // the contract code is stabilized.
    event log(string a, uint256 v);

    // Format of `inputs` matches the proof inputs exactly:
    //   IDX           VALUE
    //   00            <hash_of_vk>      (HO)
    //   01            <hash_of_vk>      (LO)
    //   02            <nested_inputs_1> (HO)
    //   03            <nested_inputs_1> (LO)
    //   ..            ...
    //   ..            ...
    //   ..            <nested_inputs_1> (HO)
    //   ..            <nested_inputs_1> (LO)
    //   ..            <result_1>        (HO)
    //   ..            <result_1>        (LO)
    //   ..            <nested_inputs_2> (HO)
    //   ..            <nested_inputs_2> (LO)
    //   ..            ...
    //   ..            ...
    //   ..            <nested_inputs_2> (HO)
    //   ..            <nested_inputs_2> (LO)
    //   ..            <result_2>        (HO)
    //   ..            <result_2>        (LO)
    //   ..            <nested_inputs_3> (HO)
    //   ..            <nested_inputs_3> (LO)
    //   ..            ...
    //   ..            ...
    //   ..            <nested_inputs_3> (HO)
    //   ..            <nested_inputs_3> (LO)
    //   ..            <result_3>        (HO)
    //   ..            <result_3>        (LO)
    //   ..            <nested_inputs_4> (HO)
    //   ..            <nested_inputs_4> (LO)
    //   ..            ...
    //   ..            ...
    //   ..            <nested_inputs_4> (HO)
    //   ..            <nested_inputs_4> (LO)
    //   ..            <result_4>        (HO)
    //   ..            <result_4>        (LO)
    //
    // `nested_parameters` are the extra parameters required by the application
    // contract (the application contract is responsible for "binding" these to
    // the nested inputs to the nested proofs).
    function process_batch(
        uint256[18] memory batch_proof,
        uint256[] memory inputs,
        uint256[] memory nested_parameters,
        IZecaleApplication target_application) public returns(bool)
    {
        // Compute expected inputs per batch (TODO: move this to the constructor)
        uint256 total_inputs =
            bw6_761_groth16.num_inputs_from_vk_length(_vk.length);
        uint256 inputs_per_batch = (total_inputs - 1) / batch_size;

        uint256 nested_parameters_per_batch =
            nested_parameters.length / batch_size;
        require(
            nested_parameters.length == batch_size * nested_parameters_per_batch,
            "invalid nested_parameters length");

        // Verify the wrapped proof.
        require(
            bw6_761_groth16.verify(_vk, batch_proof, inputs),
            "invalid wrapper proof");

        // NOTE: Here we assume that the VK hash occupies only the lower-order
        // word of the first nested input. (See notes above about scalar
        // sizes).

        // Cache the nested VK (LO word).
        uint256 nested_vk_hash = inputs[1];

        // Create an array to reuse for the nested inputs for each proof.
        uint256[] memory nested_proof_inputs =
            new uint256[](inputs_per_batch - 1);
        uint256[] memory nested_parameters_data =
            new uint256[](nested_parameters_per_batch);

        // Pass the details of each valid proof to the application
        for (uint256 nested_proof_idx = 0; nested_proof_idx < batch_size;
             ++nested_proof_idx) {

            // Of the inputs for this batch, the first `inputs_per_batch - 1`
            // are the inputs to the nested proof. The final entry is the
            // `result` for this nested proof.
            // uint256 batch_start_scalar_idx = 1 + inputs_per_batch * nested_proof_idx;
            // uint256 result_scalar_idx = batch_start_scalar_idx + (inputs_per_batch - 1);
            uint256 batch_start_word_idx =
                2 * (1 + inputs_per_batch * nested_proof_idx);
            uint256 result_word_idx =
                batch_start_word_idx + (2 * (inputs_per_batch - 1));

            // For some reason, the following Solidity code generates an
            // invalid opcode error. Hence it is replaced with the equivalent
            // assembly.
            //   uint256 result = inputs[result_word_idx + 1];
            //
            // NOTE: +1 here extracts the LO word. In the code below, we add 2
            // to skip the first word (length) in the memory representation.
            uint256 result;
            assembly
            {
                let result_byte_idx := mul(add(result_word_idx, 2), 0x20)
                result := mload(add(inputs, result_byte_idx))
            }

            if (result == 1) {
                // The nested proof is known to be valid. Copy the nested
                // inputs into their own array and invoke the application's
                // `dispatch` entry point.
                //
                // NOTE: We use knowledge of the wrapped and nested scalar
                // sizes, copying only the low-order word from wrapped inputs
                // into the array of nested inputs.
                for (uint256 i = 0; i < inputs_per_batch - 1; ++i) {
                    nested_proof_inputs[i] = inputs[batch_start_word_idx + (2 * i) + 1];
                }

                // Copy nested_parameters
                uint256 nested_parameters_start_idx =
                nested_parameters_per_batch * nested_proof_idx;
                for (uint256 i = 0; i < nested_parameters_per_batch; ++i) {
                    nested_parameters_data[i] =
                    nested_parameters[nested_parameters_start_idx + i];
                }

                target_application.dispatch(
                    nested_vk_hash,
                    nested_proof_inputs,
                    nested_parameters_data);
            }
        }

        return true;
    }
}
