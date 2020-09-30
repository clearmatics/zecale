# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.core.utils import get_zecale_dir
from zecale.cli.utils import load_verification_key, load_transaction
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


def _test_bw6_761_groth16_contract_with_proof(
        zksnark: IZKSnarkProvider,
        instance: Any,
        vk: IVerificationKey,
        proof_filename: str) -> bool:
    # Load proof and extract inputs
    extproof = load_transaction(zksnark, join(DUMMY_APP_DIR, proof_filename))
    inputs = extproof.inputs

    # Encode the vk, proof and inputs into evm words
    vk_evm_parameters = zksnark.verification_key_to_contract_parameters(vk)
    proof_evm_parameters = zksnark.proof_to_contract_parameters(extproof.proof)
    inputs_evm_parameters = hex_list_to_uint256_list(inputs)

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
        join(CONTRACTS_DIR, "bw6_761_groth16_test.sol"),
        "bw6_761_groth16_test",
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
