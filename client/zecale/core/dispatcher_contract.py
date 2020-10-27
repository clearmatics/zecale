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
DISPATCHER_SOURCE_FILE = join(CONTRACTS_DIR, "ZecaleDispatcher.sol")
DISPATCHER_DEPLOY_GAS = 5000000


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
            zksnark: IZKSnarkProvider,
            pp: PairingParameters,
            vk: IVerificationKey,
            eth_addr: str,
            eth_private_key: Optional[bytes]
    ) -> Tuple[DispatcherContract, InstanceDescription]:
        """
        Deploy the contract, returning an instance of this wrapper, and a
        description (which can be saved to a file to later instantiate).
        """
        vk_evm = zksnark.verification_key_to_contract_parameters(vk, pp)
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
            pp: PairingParameters,
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
            batch.ext_proof.proof, pp)
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
