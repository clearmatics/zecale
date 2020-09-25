# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from .utils import get_zecale_dir
from ..core.aggregated_transaction import AggregatedTransaction
from zeth.core.utils import hex_list_to_uint256_list
from zeth.core.contracts import InstanceDescription, send_contract_call
from zeth.core.zksnark import IZKSnarkProvider, IVerificationKey
# from zeth.core.zksnark import IZKSnarkProvider, GenericVerificationKey, \
#     GenericProof
from os.path import join
from typing import List, Tuple, Optional, Any


ZECALE_DIR = get_zecale_dir()
CONTRACTS_DIR = join(ZECALE_DIR, "contracts")
DISPATCHER_SOURCE_FILE = join(CONTRACTS_DIR, "zecale_dispatcher.sol")
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
            vk: IVerificationKey,
            eth_addr: str,
            eth_private_key: Optional[bytes],
            zksnark: IZKSnarkProvider) \
            -> Tuple[DispatcherContract, InstanceDescription]:
        """
        Deploy the contract, returning an instance of this wrapper, and a
        description (which can be saved to a file to later instantiate).
        """
        vk_evm = zksnark.verification_key_to_contract_parameters(vk)
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
        # object.
        proof_evm = self.zksnark.proof_to_contract_parameters(
            batch.extproof.proof)
        inputs_evm = hex_list_to_uint256_list(batch.extproof.inputs)

        # Should be:
        #   nested_parameters_evm: List[List[int]] =
        #       [hex_list_to_uint256_list(params)
        #        for params in batch.nested_parameters]
        # but we flatten the list in order to work around issues passing 2d
        # arrays to contracts.
        nested_parameters_evm: List[int] = sum(
            [hex_list_to_uint256_list(params)
             for params in batch.nested_parameters],
            [])

        contract_call = self.instance.functions.process_batch(
            proof_evm,
            inputs_evm,
            nested_parameters_evm,
            application_contract_address)

        # Broadcast the call
        return send_contract_call(
            self.web3,
            contract_call,
            eth_addr,
            eth_private_key,
            None,               # TODO: value (fee?)
            None)
