# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zecale.core.utils import get_zecale_dir
from zecale.core.aggregated_transaction import AggregatedTransaction
from zeth.core.utils import hex_list_to_uint256_list
from zeth.core.pairing import PairingParameters
from zeth.core.contracts import InstanceDescription, send_contract_call
from zeth.core.zksnark import IZKSnarkProvider, IVerificationKey
# from zeth.core.zksnark import IZKSnarkProvider, GenericVerificationKey, \
#     GenericProof
from web3.utils.contracts import find_matching_event_abi  # type: ignore
from web3.utils.events import get_event_data  # type: ignore
from os.path import join
from typing import Tuple, Optional, Any


ZECALE_DIR = get_zecale_dir()
CONTRACTS_DIR = join(ZECALE_DIR, "contracts")
DISPATCHER_SOURCE_FILE = join(CONTRACTS_DIR, "zecale_dispatcher.sol")
DISPATCHER_DEPLOY_GAS = 5000000


# Temporarily hard-code the pairing parameters for BW6-761
# pylint: disable=line-too-long
PAIRING_PARAMETERS = PairingParameters.from_json_dict({
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


class DispatcherContract:
    """
    Wrapper around operations on the zecale dispatcher contract.
    """

    def __init__(
            self,
            web3: Any,
            instance_desc: InstanceDescription,
            zksnark: IZKSnarkProvider):
        self.web3 = web3
        self.instance = instance_desc.instantiate(web3)
        self.zksnark = zksnark

    @staticmethod
    def deploy(
            web3: Any,
            vk: IVerificationKey,
            eth_addr: str,
            eth_private_key: Optional[bytes],
            zksnark: IZKSnarkProvider) \
            -> Tuple[DispatcherContract, InstanceDescription]:
        """
        Deploy the contract, returning an instance of this wrapper, and a
        description (which can be saved to a file to later instantiate).
        """
        vk_evm = zksnark.verification_key_to_contract_parameters(
            vk, PAIRING_PARAMETERS)
        instance_desc = InstanceDescription.deploy(
            web3,
            DISPATCHER_SOURCE_FILE,
            "ZecaleDispatcher",
            eth_addr,
            eth_private_key,
            DISPATCHER_DEPLOY_GAS,
            {"allow_paths": CONTRACTS_DIR},
            [vk_evm])
        return DispatcherContract(web3, instance_desc, zksnark), instance_desc

    def process_batch(
            self,
            batch: AggregatedTransaction,
            application_contract_address: str,
            eth_addr: str,
            eth_private_key: Optional[bytes]) -> bytes:
        """
        Send a batch to the contracts process_batch entry point. Returns the
        transaction ID.
        """

        # Encode the parameters of the entry point and create a local call
        # object. The proof and inputs are encoded into contract parameters,
        # and the nested_parameters are passed as raw bytes arrays.
        proof_evm = self.zksnark.proof_to_contract_parameters(
            batch.ext_proof.proof, PAIRING_PARAMETERS)
        inputs_evm = hex_list_to_uint256_list(batch.ext_proof.inputs)

        contract_call = self.instance.functions.process_batch(
            proof_evm,
            inputs_evm,
            hex_list_to_uint256_list([p.hex() for p in batch.nested_parameters]),
            application_contract_address)

        # Broadcast the call
        return send_contract_call(
            self.web3,
            contract_call,
            eth_addr,
            eth_private_key,
            None,               # TODO: value (fee?)
            None)

    def dump_logs(self, tx_receipt: Any) -> None:
        """
        Print out debug log information from a dispatcher invocation
        """
        event_abi = find_matching_event_abi(self.instance.abi, event_name="log")
        logs = tx_receipt.logs
        for log in logs:
            event_data = get_event_data(event_abi, log)
            print(f"{event_data.args['a']}: {event_data.args['v']}")
