// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "./Groth16BW6_761.sol";
import "./IZecaleApplication.sol";

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

    uint256 constant scalar_size_in_words = 2;

    // Verification key
    uint256[] _vk;

    // Total number of inputs expected
    uint256 _total_inputs;

    // Number of inputs per nested proof (note that this includes the result)
    uint256 _inputs_per_nested_tx;

    // Constructor for Zecale contract. Initializes the batch verification key.
    // `vk` is passed as the verification key encoded as uint256 array, in the
    // format described in Groth16BW6_761.sol.
    constructor(uint256[] memory vk) public
    {
        _vk = vk;
        // Compute expected inputs per batch (-2 for vk_hash and results)
        _total_inputs = Groth16BW6_761.num_inputs_from_vk_length(vk.length);
        _inputs_per_nested_tx = (_total_inputs - 2) / batch_size;
    }

    // Event logger to aid contract debugging. Can be removed eventually when
    // the contract code is stabilized.
    event log(string a, uint256 v);

    // Format of `inputs` matches the proof inputs exactly:
    //   IDX           VALUE
    //   00            <hash_of_vk>      (HO)
    //   01            <hash_of_vk>      (LO)
    //   02            <results>         (HO)
    //   03            <results>         (LO)
    //   04            <nested_inputs_1> (HO) ---
    //   05            <nested_inputs_1> (LO)   |
    //   ..            ...                      |
    //   ..            ...                     nested_tx_1
    //   ..            <nested_inputs_1> (HO)   |
    //   ..            <nested_inputs_1> (LO) __|
    //   ..                     ...           ...
    //   ..            <nested_inputs_N> (HO) ---
    //   ..            <nested_inputs_N> (LO)   |
    //   ..            ...                      |
    //   ..            ...                     nested_tx_N
    //   ..            <nested_inputs_N> (HO)   |
    //   ..            <nested_inputs_N> (LO) __|
    //
    // `nested_parameters` are the extra parameters required by the application
    // contract (the application contract is responsible for "binding" these to
    // the nested inputs to the nested proofs).
    function process_batch(
        uint256[18] memory batch_proof,
        uint256[] memory inputs,
        bytes[] memory nested_parameters,
        IZecaleApplication target_application) public returns(bool)
    {
        // TODO: Remove this (and all emit log calls below) once code is more
        // thoroughly tested.

        // emit log("_total_inputs", _total_inputs);
        // emit log("_inputs_per_nested_tx", _inputs_per_nested_tx);
        // for (uint256 i = 0 ; i < inputs.length ; ++i) {
        //     emit log("i", inputs[i]);
        // }

        require(
            inputs.length == _total_inputs * scalar_size_in_words,
            "invalid inputs length");
        require(
            nested_parameters.length == batch_size,
            "invalid nested_parameters length");

        // Verify the wrapped proof.
        require(
            Groth16BW6_761.verify(_vk, batch_proof, inputs),
            "invalid wrapper proof");

        // NOTE: Here we assume that the VK hash occupies only the lower-order
        // word of the first nested input. (See notes above about scalar
        // sizes).

        // Cache the nested VK (LO word) to pass to the application.
        uint256[2] memory nested_vk_hash;
        nested_vk_hash[0] = inputs[0];
        nested_vk_hash[1] = inputs[1];
        uint256 inputs_per_nested_tx = _inputs_per_nested_tx;

        // Create an array to reuse to pass the nested inputs to the
        // application (note that the result is not passed, hence -1).
        uint256[] memory nested_proof_inputs =
            new uint256[](_inputs_per_nested_tx);

        // Result bits
        uint256 results = inputs[3];

        // Pass the details of each valid proof to the application
        for (uint256 nested_tx_idx = 0; nested_tx_idx < batch_size;
             ++nested_tx_idx) {

            uint256 result = results & 0x1;
            results = results >> 1;

            // Skip nested transactions whose proofs are invalid.
            // emit log("result", result);
            if (result == 0) {
                continue;
            }

            // Note that the offsets here are all based on the assumption that
            // each scalar consists of scalar_size_in_words uint256 words, and
            // that each nested input is held in the final uint256 word.

            // Word index (in `inputs`) of the start of the inputs for this
            // nested tx. +1 to target LO word.
            uint256 batch_start_word_idx =
                scalar_size_in_words *
                    (2 + inputs_per_nested_tx * nested_tx_idx)
                + 1;
            // emit log("batch_start_word_idx", batch_start_word_idx);

            // The nested proof is known to be valid. Copy the nested
            // inputs into their own array and invoke the application's
            // `dispatch` entry point.
            //
            // NOTE: We use knowledge of the wrapped and nested scalar
            // sizes, copying only the low-order word from wrapped inputs
            // into the array of nested inputs.
            for (uint256 i = 0; i < inputs_per_nested_tx; ++i) {
                nested_proof_inputs[i] = inputs[
                    batch_start_word_idx + (scalar_size_in_words * i)];
                // emit log("ni", nested_proof_inputs[i]);
            }

            target_application.dispatch(
                nested_vk_hash,
                nested_proof_inputs,
                nested_parameters[nested_tx_idx]);
        }

        return true;
    }
}
