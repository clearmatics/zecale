// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Implementation notes:
//
// Element sizes
// -------------
//   Fr:  2 x uint256 = 64  bytes = 0x40 bytes
//   Fq:  3 x uint256 = 96  bytes = 0x60 bytes
//   G1:  6 x uint256 = 192 bytes = 0xc0 bytes
//   G2:  6 x uint256 = 192 bytes = 0xc0 bytes
//
// Generator g_2 of G2
// -------------------
//   x = 0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6bace6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c
//   y = 0x0017c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe3160a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa823003ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61
//
// which, encoded as evm words, is:
//
//   x = [
//     0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d,
//     0x26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6ba,
//     0xce6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c,
//   ]
//   y = [
//     0x0017c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe316,
//     0x0a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa82300,
//     0x3ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61,
//   ]

library bw6_761_groth16
{
    // Structure of the verification key array:
    // struct VerificationKey
    // {
    //     uint256[6] alpha;   // offset 0x00 words (0x000 bytes)
    //     uint256[6] beta;    // offset 0x06 words (0x0c0 bytes)
    //     uint256[6] delta;   // offset 0x0c words (0x180 bytes)
    //     uint256[] abc;      // offset 0x12 words (0x240 bytes)
    // }

    // Structure of the proof array:
    // struct Proof
    // {
    //     uint256[6] a;       // offset 0x00 words (0x000 bytes)
    //     uint256[6] minus_b; // offset 0x06 words (0x0c0 bytes)
    //     uint256[6] c;       // offset 0x0c words (0x180 bytes)
    // }

    /// Verify a proof and inputs (both in memory) against a verification key
    /// (in storage). Note that the code is highly dependent on these
    /// locations.
    function verify(
        uint256[] storage vk,
        uint256[18] memory proof,
        uint256[] memory inputs) internal returns(bool)
    {
        // Compute expected number of inputs.
        uint256 num_inputs = ((vk.length - 0x12) / 6) - 1;
        require(
            (inputs.length / 2) == num_inputs,
            "Input length differs from expected");

        // Memory scratch pad, large enough to accomodate the max used size
        // (see layout diagrams below).
        uint256[24] memory pad;
        bool result = true;
        uint256 vk_slot_num;

        // 1. Compute the linear combination
        //   accum = \sum_{i=0}^{l} input[i] * abc[i]  (in G1).
        //
        // Write abc[0] to (accum_x, accum_y) (input[0] is implicitly 1). In
        // each iteration for i=1,..,l, use abc_x[i] and input[i] (index i-1)
        // to perform scalar multiplication using ecmul and ecadd. Elements
        // written to pad as follows, so that ecmul and ecadd output their
        // results directly into the correct locations.
        //
        //  OFFSET  USAGE
        //   0x1c0    <END>          ECMUL               ECADD
        //   0x1a0    input_i     --
        //   0x180    input_i      |
        //   0x160    abc_y        |     --           --
        //   0x140    abc_y        | IN   |            |
        //   0x120    abc_y        |      |            |
        //   0x100    abc_x        |      | OUT        |
        //   0x0e0    abc_x        |      |            | IN     ecadd
        //   0x0c0    abc_x       --     --            |
        //   0x0a0    accum_y                          |    --
        //   0x080    accum_y                          |     |
        //   0x060    accum_y                          |     | OUT
        //   0x040    accum_x                          |     |
        //   0x020    accum_x                          |     |
        //   0x000    accum_x                         --    --

        assembly {

            // Copied from bn implementation in zeth.
            let g := sub(gas, 2000)

            // Compute starting slot of the vk data and abc data.
            mstore(pad, vk_slot)
            vk_slot_num := keccak256(pad, 0x20)
            let abc_slot_num := add(vk_slot_num, 0x12)

            // Skip first word of `inputs`. Compute the end of the array (each
            // element is 0x40 bytes).
            let input_i := add(inputs, 0x20)
            let input_end := add(input_i, mul(num_inputs, 0x40))

            // Initialize 6 words of (accum_x, accum_y), as first element of proof.abc
            mstore(pad, sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0x20), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0x40), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0x60), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0x80), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0xa0), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)

            // Note the location of abc (the area used for scalar multiplication)
            let mul_in := add(pad, 0x0c0)

            // For each input ...
            for
                {}
                lt(input_i, input_end)
                {}
            {
                // Copy proof.abc from storage into the pad
                mstore(mul_in, sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0x20), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0x40), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0x60), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0x80), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0xa0), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)

                // Copy input into the pad
                mstore(add(mul_in, 0xc0), mload(input_i))
                input_i := add(input_i, 0x20)
                mstore(add(mul_in, 0xe0), mload(input_i))
                input_i := add(input_i, 0x20)

                // Call ecmul on (abc_i, input_i), then ecadd on (accum, abc_i)
                let s1 := call(g, 0xc2, 0, mul_in, 0x100, mul_in, 0xc0)
                let s2 := call(g, 0xc1, 0, pad, 0x180, pad, 0x0c0)
                result := and(result, and(s1, s2))
            }
        }

        require(result, "failure in input accumulation");

        // 2. Write all elements of the pairing check:
        //   e(a, b) =
        //       e(vk.alpha, vk.beta) * e(accum, g_2) * e(c, vk.delta)
        // where:
        //   e: G_1 x G_2 -> G_T is a bilinear map
        //   `*`: denote the group operation in G_T
        //
        // Verification is performed via ecpairing, as:
        //     e(a, b) * e(accum, -g_2) * e(vk.alpha, -vk.beta) *
        //         e(c, -vk.delta) == 1
        // (note that beta and delta in the VK are therefore uploaded as
        // negated values).

        //  OFFSET  USAGE
        //   0x600          <END>
        //   0x540~0x600    vk.delta
        //   0x480~0x540    proof.c
        //   0x3c0~0x480    proof.minus_b
        //   0x300~0x3c0    proof.a
        //   0x240~0x300    vk.beta
        //   0x180~0x240    vk.alpha
        //   0x0c0~0x180    g_2
        //   0x000~0x0c0    accum

        assembly
        {
            // accum already in place

            // Write g_2
            mstore(
                add(pad, 0x0c0),
                0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d)
            mstore(
                add(pad, 0x0e0),
                0x26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6ba)
            mstore(
                add(pad, 0x100),
                0xce6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c)
            mstore(
                add(pad, 0x120),
                0x0017c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe316)
            mstore(
                add(pad, 0x140),
                0x0a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa82300)
            mstore(
                add(pad, 0x160),
                0x3ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61)

            // write vk.alpha and vk.beta
            mstore(add(pad, 0x180), sload(vk_slot_num))
            mstore(add(pad, 0x1a0), sload(add(vk_slot_num,  1)))
            mstore(add(pad, 0x1c0), sload(add(vk_slot_num,  2)))
            mstore(add(pad, 0x1e0), sload(add(vk_slot_num,  3)))
            mstore(add(pad, 0x200), sload(add(vk_slot_num,  4)))
            mstore(add(pad, 0x220), sload(add(vk_slot_num,  5)))

            mstore(add(pad, 0x240), sload(add(vk_slot_num,  6)))
            mstore(add(pad, 0x260), sload(add(vk_slot_num,  7)))
            mstore(add(pad, 0x280), sload(add(vk_slot_num,  8)))
            mstore(add(pad, 0x2a0), sload(add(vk_slot_num,  9)))
            mstore(add(pad, 0x2c0), sload(add(vk_slot_num, 10)))
            mstore(add(pad, 0x2e0), sload(add(vk_slot_num, 11)))

            // write proof.a and proof.minus_b
            mstore(add(pad, 0x300), mload(proof))
            mstore(add(pad, 0x320), mload(add(proof, 0x020)))
            mstore(add(pad, 0x340), mload(add(proof, 0x040)))
            mstore(add(pad, 0x360), mload(add(proof, 0x060)))
            mstore(add(pad, 0x380), mload(add(proof, 0x080)))
            mstore(add(pad, 0x3a0), mload(add(proof, 0x0a0)))

            mstore(add(pad, 0x3c0), mload(add(proof, 0x0c0)))
            mstore(add(pad, 0x3e0), mload(add(proof, 0x0e0)))
            mstore(add(pad, 0x400), mload(add(proof, 0x100)))
            mstore(add(pad, 0x420), mload(add(proof, 0x120)))
            mstore(add(pad, 0x440), mload(add(proof, 0x140)))
            mstore(add(pad, 0x460), mload(add(proof, 0x160)))

            // write proof.c, followed by vk.delta
            mstore(add(pad, 0x480), mload(add(proof, 0x180)))
            mstore(add(pad, 0x4a0), mload(add(proof, 0x1a0)))
            mstore(add(pad, 0x4c0), mload(add(proof, 0x1c0)))
            mstore(add(pad, 0x4e0), mload(add(proof, 0x1e0)))
            mstore(add(pad, 0x500), mload(add(proof, 0x200)))
            mstore(add(pad, 0x520), mload(add(proof, 0x220)))

            mstore(add(pad, 0x540), sload(add(vk_slot_num, 12)))
            mstore(add(pad, 0x560), sload(add(vk_slot_num, 13)))
            mstore(add(pad, 0x580), sload(add(vk_slot_num, 14)))
            mstore(add(pad, 0x5a0), sload(add(vk_slot_num, 15)))
            mstore(add(pad, 0x5c0), sload(add(vk_slot_num, 16)))
            mstore(add(pad, 0x5e0), sload(add(vk_slot_num, 17)))

            // Call ecpairing
            result := call(gas, 0xc3, 0, pad, 0x600, pad, 0x20)
        }

        return 1 == pad[0];
    }

    /// Given the length of a verification key, encoded as a uint256 array,
    /// compute the number of inputs per batch.
    function inputs_per_batch_from_vk_length(uint256 vk_length) internal returns (uint256) {
        // See the format of vk above
        return ((vk_length - 0x12) / 6) - 1;
    }
}
