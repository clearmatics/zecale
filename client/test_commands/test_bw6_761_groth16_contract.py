# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.core.utils import get_zecale_dir
from zecale.cli.utils import load_verification_key, load_aggregated_transaction
from zeth.core.pairing import PairingParameters
from zeth.core.zksnark import IZKSnarkProvider, Groth16, IVerificationKey
from zeth.core.utils import hex_list_to_uint256_list
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import get_eth_network, open_web3_from_network
from os.path import join
import sys
from typing import Any


ZECALE_DIR = get_zecale_dir()
CONTRACTS_DIR = join(ZECALE_DIR, "contracts")
DUMMY_APP_DIR = join(ZECALE_DIR, "testdata", "dummy_app")


# Pairing parameters for BW6-761
# pylint: disable=line-too-long
BW6_761_PAIRING_PARAMETERS = PairingParameters.from_json_dict({
    "name": "bw6-761",
    "r": "0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001",  # noqa
    "q": "0x0122e824fb83ce0ad187c94004faff3eb926186a81d14688528275ef8087be41707ba638e584e91903cebaff25b423048689c8ed12f9fd9071dcd3dc73ebff2e98a116c25667a8f8160cf8aeeaf0a437e6913e6870000082f49d00000000008b",  # noqa
    "generator_g1": [
        "0x01075b020ea190c8b277ce98a477beaee6a0cfb7551b27f0ee05c54b85f56fc779017ffac15520ac11dbfcd294c2e746a17a54ce47729b905bd71fa0c9ea097103758f9a280ca27f6750dd0356133e82055928aca6af603f4088f3af66e5b43d",  # noqa
        "0x0058b84e0a6fc574e6fd637b45cc2a420f952589884c9ec61a7348d2a2e573a3265909f1af7e0dbac5b8fa1771b5b806cc685d31717a4c55be3fb90b6fc2cdd49f9df141b3053253b2b08119cad0fb93ad1cb2be0b20d2a1bafc8f2db4e95363"  # noqa
    ],
    "generator_g2": [
        "0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6bace6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c",  # noqa
        "0x0017c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe3160a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa823003ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61"  # noqa
    ],
})
# pylint: enable=line-too-long


def _test_bw6_761_groth16_contract_with_proof(
        zksnark: IZKSnarkProvider,
        instance: Any,
        vk: IVerificationKey,
        tx_filename: str) -> bool:
    # Load proof and extract inputs
    tx = load_aggregated_transaction(zksnark, join(DUMMY_APP_DIR, tx_filename))
    ext_proof = tx.ext_proof

    # Encode the vk, proof and inputs into evm words
    vk_evm_parameters = zksnark.verification_key_to_contract_parameters(
        vk, BW6_761_PAIRING_PARAMETERS)
    proof_evm_parameters = zksnark.proof_to_contract_parameters(
        ext_proof.proof, BW6_761_PAIRING_PARAMETERS)
    inputs_evm_parameters = hex_list_to_uint256_list(ext_proof.inputs)

    # Execute the test contract and return the result
    evm_parameters = [
        vk_evm_parameters,
        proof_evm_parameters,
        inputs_evm_parameters
    ]

    return instance.functions.test_verify(*evm_parameters).call()


def test_bw6_761_groth16_valid(
        zksnark: IZKSnarkProvider,
        instance: Any,
        aggregator_vk: IVerificationKey) -> None:
    assert _test_bw6_761_groth16_contract_with_proof(
        zksnark, instance, aggregator_vk, "batch1.json")


def test_bw6_761_groth16_invalid(
        zksnark: IZKSnarkProvider,
        instance: Any,
        aggregator_vk: IVerificationKey) -> None:
    assert not _test_bw6_761_groth16_contract_with_proof(
        zksnark, instance, aggregator_vk, "batch1-invalid.json")


def main() -> int:
    web3: Any = open_web3_from_network(get_eth_network(None))
    bw6_761_groth16_instance_desc = InstanceDescription.deploy(
        web3,
        join(CONTRACTS_DIR, "Groth16BW6_761_test.sol"),
        "Groth16BW6_761_test",
        web3.eth.accounts[0],  # pylint: disable=no-member
        None,
        500000,
        {"allow_paths": CONTRACTS_DIR})

    bw6_761_groth16_instance = bw6_761_groth16_instance_desc.instantiate(web3)
    zksnark = Groth16()
    aggregator_vk = load_verification_key(
        zksnark, join(DUMMY_APP_DIR, "aggregator_vk.json"))

    test_bw6_761_groth16_valid(zksnark, bw6_761_groth16_instance, aggregator_vk)
    test_bw6_761_groth16_invalid(zksnark, bw6_761_groth16_instance, aggregator_vk)

    print("========================================")
    print("==              PASSED                ==")
    print("========================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
