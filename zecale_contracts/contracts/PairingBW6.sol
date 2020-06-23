// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.6.9;

// Several pairing-related utility functions over BW6-761.
//
// - 1 Ethereum word is 256-bit long
// - 1 BW6-761 base field element is 761-bit long
// - 1 BW6-761 scalar field element is 377-bit long
// Thus,
// - 3 Ethereum words are necessary to represent 1 base field element,
// - 2 Ethereum words are necessary to represent 1 scalar field element
//
// NOTE:
// This implementation matches: https://github.com/clearmatics/libff/tree/develop/libff/algebra/curves/bw6_761
//
// [Sagemath excerpt]
// q = 0x122e824fb83ce0ad187c94004faff3eb926186a81d14688528275ef8087be41707ba638e584e91903cebaff25b423048689c8ed12f9fd9071dcd3dc73ebff2e98a116c25667a8f8160cf8aeeaf0a437e6913e6870000082f49d00000000008b
// q.digits(base=2**256)
// # [69036172439834594078135912819926461842834193110597730425838344000302431076491,
// #  50877508454115348380452006117144225713256344386170928517592842154234937605934,
// #  513987850983873464006802627883984196151100700201527873469053252827320139329]
// r = 0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001
// r.digits(base=2**256)
// # [11821711093692503419202826048817742432896994856600506088868478158150448447489,
// #  2233869582254757176697208567811361083]

library PairingBW6 {
    struct G1Point {
        // X = (2^256)^2 * X[2] + (2^256) * X[1] + X[0]
        uint256[3] X;
        // Y = (2^256)^2 * Y[2] + (2^256) * Y[1] + Y[0]
        uint256[3] Y;
    }

    struct G2Point {
        // X = (2^256)^2 * X[2] + (2^256) * X[1] + X[0]
        uint256[3] X;
        // Y = (2^256)^2 * Y[2] + (2^256) * Y[1] + Y[0]
        uint256[3] Y;
    }

    // Return the generator of G1
    // [CPP code] bw6_761_G1::G1_one = bw6_761_G1(bw6_761_Fq("6238772257594679368032145693622812838779005809760824733138787810501188623461307351759238099287535516224314149266511977132140828635950940021790489507611754366317801811090811367945064510304504157188661901055903167026722666149426237"), bw6_761_Fq("2101735126520897423911504562215834951148127555913367997162789335052900271653517958562461315794228241561913734371411178226936527683203879553093934185950470971848972085321797958124416462268292467002957525517188485984766314758624099"), bw6_761_Fq::one());
    function P1() internal pure returns (G1Point memory) {
        return G1Point(
            [
                1564650758105937227603989093386247915746576368743371713829685500761952597053,
                54732504807773012332754196408542921042092393462712171500558398132721566746993,
                465308892415002654953065456525087219612465462459131508665556745963670171591
            ],
            [
                72196803006028709943418975574124549059167347351310937004421858012097726206819,
                17345206266475173360034276017504102690467590100150719034410668061296488009172,
                156754567003250291243731216346527801582526905538558216352598772436928132003
            ]
        );
    }

    // Return the generator of G2
    // [CPP code] bw6_761_G2::G2_one = bw6_761_G2(bw6_761_Fq("6445332910596979336035888152774071626898886139774101364933948236926875073754470830732273879639675437155036544153105017729592600560631678554299562762294743927912429096636156401171909259073181112518725201388196280039960074422214428"), bw6_761_Fq("562923658089539719386922163444547387757586534741080263946953401595155211934630598999300396317104182598044793758153214972605680357108252243146746187917218885078195819486220416605630144001533548163105316661692978285266378674355041"), bw6_761_Fq::one());
    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [
                93362468154965889406159977045877777339850179488624463258909135579530641170204,
                17506116492030738917738374491395977723144033117807518758130866273164430784186,
                480714889732506316189785004296967363818202760342591104622025872910079037293
            ],
            [
                28342765395199459737620840414410381192229788244464125304317823543208887925601,
                4575297277931036775734398678523257403449434763871952914757560229922140070656,
                41984764476854328464533355296902683169556237593793090984290269116703433494
            ]
        );
    }

    // TODO: Think about adding a negation precompiled to avoid expensive/long field
    // arithmetic in solidity.
    //
    // Return the negation of p, i.e. p.add(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // TODO
    }

    // Return the sum of two points of G1
    function add(G1Point memory p1, G1Point memory p2)
        internal
        returns (G1Point memory r) {
        uint256[3][4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            // Call bw6761Add([p1.X, p1.Y, p2.X, p2.Y])
            // 1. Pre-compiled contract assumed to be at address: 20 (change if necessary)
            // 2. Input size = 3 * 4 * 32 = 384 bytes =  0x180
            // 3. Output size = 192 bytes = 0xc0
            success := call(sub(gas(), 2000), 20, 0, input, 0x180, r, 0xc0)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(
            success,
            "Call to the bw6761Add precompiled failed (probably an out of gas error?)"
        );
    }

    // Return the product of a point on G1 and a scalar, i.e.
    // p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function mul(G1Point memory p, uint256[2] s)
        internal
        returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            // Call bw6761ScalarMul([p1.X, p1.Y, s])
            // 1. Pre-compiled contract assumed to be at address: 21 (change if necessary)
            // 2. Input size = 192 bytes (Group el) + 64 bytes (scalar) = 256 bytes =  0x100
            // 3. Output size = 192 bytes = 0xc0
            success := call(sub(gas(), 2000), 21, 0, input, 0x100, r, 0xc0)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require (
            success,
            "Call to bn256ScalarMul failed (probably an out of gas error?)"
        );
    }

    // Return the result of computing the pairing check
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        returns (bool) {
        require(
            p1.length == p2.length,
            "Mismatch between the number of elements in G1 and elements in G2"
        );
        // For each pairing check we have 2 coordinates for the elements in
        // G1 and G2. Each coordinate needs 3 Ethereum words to be represented
        uint256 elements = p1.length;
        // One pairing computation: e(P,Q) takes P \in G1 (2 * 3 Ethereum words)
        // and Q \in G2 (2 * 3 Ethereum words). Thus, in total, we process
        // 2 * 3 + 2 * 3 = 12 Ethereum words for a pairing computation.
        uint256 inputSize = elements * 12;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++)
        {
            // Curve point (G1) - 2 coordinates of 96 bytes (0x60 in hex)
            input[i * 12 + 0] = p1[i].X[0];
            input[i * 12 + 1] = p1[i].X[1];
            input[i * 12 + 2] = p1[i].X[2];
            input[i * 12 + 3] = p1[i].Y[0];
            input[i * 12 + 4] = p1[i].Y[1];
            input[i * 12 + 5] = p1[i].Y[2];
            // Twist point (G2) - 2 coordinates of 96 bytes (0x60 in hex)
            input[i * 12 + 6] = p2[i].X[0];
            input[i * 12 + 7] = p2[i].X[1];
            input[i * 12 + 8] = p2[i].X[2];
            input[i * 12 + 9] = p2[i].Y[0];
            input[i * 12 + 10] = p2[i].Y[1];
            input[i * 12 + 11] = p2[i].Y[2];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            // We assume that the bw6761Pairing precompiled contract has the
            // same interface as the `bn254Pairing` precompiled.
            // As such, here we assume that the bw6761Pairing precompiled takes an
            // input of size N * 384 (a set of pairs of elements (g1, g2) \in G1 x G2
            // has a size of 384 bytes), and carries out a pairing check (not a pairing!)
            // (ie: the result is a boolean, not an element in G_T).
            //
            // - Pre-compiled contract assumed to be at address: 22 (change if necessary)
            success := call(sub(gas(), 2000), 22, 0, add(input, 0x20), mul(inputSize, 0x60), out, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(
            success,
            "Call to the bw6761Pairing precompiled failed (probably an out of gas error?)"
        );

        return out[0] != 0;
    }

    // Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    // Convenience method for a pairing check for three pairs.
    function pairingProd3(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    // Convenience method for a pairing check for 4 pairs.
    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}