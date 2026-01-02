"""
Monkey patch to fix the operate library's hardcoded safe_tx_gas=0 issue.

This patch overrides GnosisSafeTransaction.build() to use a reasonable gas estimate
instead of hardcoding safe_tx_gas=0, which causes GS013 errors.

Import this module BEFORE importing any operate modules for the patch to take effect.
"""

import typing as t


def patch_safe_gas_estimation():
    """
    Patch the operate library to fix safe_tx_gas estimation.
    """
    try:
        from operate.services.protocol import GnosisSafeTransaction
        from autonomy.chain.base import registry_contracts
        from operate.utils.gnosis import SafeOperation
        from operate.data import ContractConfigs
        from operate.services.protocol import (
            hash_payload_to_hex,
            skill_input_hex_to_payload,
        )
        import binascii

        # Store the original build method
        original_build = GnosisSafeTransaction.build

        def patched_build(self, *args: t.Any, **kwargs: t.Any) -> t.Dict:
            """Patched build method that uses estimated gas instead of 0."""
            # Build multisend data (same as original)
            multisend_data = bytes.fromhex(
                registry_contracts.multisend.get_tx_data(
                    ledger_api=self.ledger_api,
                    contract_address=ContractConfigs.multisend.contracts[
                        self.chain_type
                    ],
                    multi_send_txs=self._txs,
                ).get("data")[2:]
            )

            # Use a reasonable gas estimate instead of 0
            # When safeTxGas=0, Safe uses all remaining gas, but this causes GS013 errors
            # Use a high default (2M gas) which should be more than enough for any Safe transaction
            # This prevents GS013 while still allowing the transaction to execute
            estimated_safe_tx_gas = 2_000_000

            # Use estimated gas instead of 0
            safe_tx_hash = registry_contracts.gnosis_safe.get_raw_safe_transaction_hash(
                ledger_api=self.ledger_api,
                contract_address=self.safe,
                value=0,
                safe_tx_gas=estimated_safe_tx_gas,  # Use estimated gas instead of 0
                to_address=ContractConfigs.multisend.contracts[self.chain_type],
                data=multisend_data,
                operation=SafeOperation.DELEGATE_CALL.value,
            ).get("tx_hash")[2:]

            payload_data = hash_payload_to_hex(
                safe_tx_hash=safe_tx_hash,
                ether_value=0,
                safe_tx_gas=estimated_safe_tx_gas,  # Use estimated gas instead of 0
                to_address=ContractConfigs.multisend.contracts[self.chain_type],
                operation=SafeOperation.DELEGATE_CALL.value,
                data=multisend_data,
            )

            owner = self.ledger_api.api.to_checksum_address(self.crypto.address)
            tx_params = skill_input_hex_to_payload(payload=payload_data)
            safe_tx_bytes = binascii.unhexlify(tx_params["safe_tx_hash"])
            signatures = {
                owner: self.crypto.sign_message(
                    message=safe_tx_bytes,
                    is_deprecated_mode=True,
                )[2:]
            }

            tx = registry_contracts.gnosis_safe.get_raw_safe_transaction(
                ledger_api=self.ledger_api,
                contract_address=self.safe,
                sender_address=owner,
                owners=(owner,),  # type: ignore
                to_address=tx_params["to_address"],
                value=tx_params["ether_value"],
                data=tx_params["data"],
                safe_tx_gas=tx_params[
                    "safe_tx_gas"
                ],  # This will now have the estimated value
                signatures_by_owner=signatures,
                operation=SafeOperation.DELEGATE_CALL.value,
                nonce=self.ledger_api.api.eth.get_transaction_count(owner),
            )
            return t.cast(t.Dict, tx)

        # Replace the build method
        GnosisSafeTransaction.build = patched_build

        return True

    except Exception:
        # Silently fail if patch can't be applied
        return False


# This module should be imported and patch_safe_gas_estimation() called
# BEFORE any operate modules that use GnosisSafeTransaction are imported


