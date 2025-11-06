"""Automate staking reward claims via the configured multisig Safe."""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from eth_account import Account
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3
from web3.exceptions import ContractLogicError
from web3.middleware import geth_poa_middleware


OPERATE_HOME = Path.cwd() / ".operate"
SCRIPT_PATH = Path(__file__).resolve().parent
STAKING_TOKEN_JSON_PATH = SCRIPT_PATH / "contracts" / "StakingToken.json"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


SAFE_ABI = [
    {
        "inputs": [],
        "name": "nonce",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"},
            {"internalType": "bytes", "name": "data", "type": "bytes"},
            {"internalType": "uint8", "name": "operation", "type": "uint8"},
            {"internalType": "uint256", "name": "safeTxGas", "type": "uint256"},
            {"internalType": "uint256", "name": "baseGas", "type": "uint256"},
            {"internalType": "uint256", "name": "gasPrice", "type": "uint256"},
            {"internalType": "address", "name": "gasToken", "type": "address"},
            {"internalType": "address", "name": "refundReceiver", "type": "address"},
            {"internalType": "uint256", "name": "_nonce", "type": "uint256"},
        ],
        "name": "getTransactionHash",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"},
            {"internalType": "bytes", "name": "data", "type": "bytes"},
            {"internalType": "uint8", "name": "operation", "type": "uint8"},
            {"internalType": "uint256", "name": "safeTxGas", "type": "uint256"},
            {"internalType": "uint256", "name": "baseGas", "type": "uint256"},
            {"internalType": "uint256", "name": "gasPrice", "type": "uint256"},
            {"internalType": "address", "name": "gasToken", "type": "address"},
            {
                "internalType": "address payable",
                "name": "refundReceiver",
                "type": "address",
            },
            {"internalType": "bytes", "name": "signatures", "type": "bytes"},
        ],
        "name": "execTransaction",
        "outputs": [{"internalType": "bool", "name": "success", "type": "bool"}],
        "stateMutability": "payable",
        "type": "function",
    },
]


class ClaimAutomationError(RuntimeError):
    """Raised when the claim automation cannot proceed."""


@dataclass
class StakingContext:
    """Holds staking-related configuration."""

    chain_name: str
    rpc_url: str
    staking_contract: str
    service_id: int
    operator_private_key: str
    service_multisig: Optional[str]


def checksum(address: str) -> str:
    """Return a checksum address."""

    if not address:
        raise ClaimAutomationError("Missing address while computing checksum.")
    return Web3.to_checksum_address(address)


def load_wallet_safe(chain_name: str) -> str:
    """Load the Safe address for the given chain."""

    wallet_path = OPERATE_HOME / "wallets" / "ethereum.json"
    try:
        wallet_data = json.loads(wallet_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - configuration error
        raise ClaimAutomationError(
            f"Ethereum wallet file not found at {wallet_path}"
        ) from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - configuration error
        raise ClaimAutomationError("Invalid JSON in ethereum wallet file.") from exc

    safes = wallet_data.get("safes", {})
    safe_address = safes.get(chain_name)
    if not safe_address:
        raise ClaimAutomationError(
            f"Safe address for chain '{chain_name}' not found in ethereum wallet."
        )

    return safe_address


def find_staking_context() -> StakingContext:
    """Discover staking configuration from the Operate metadata."""

    services_dir = OPERATE_HOME / "services"
    if not services_dir.exists():
        raise ClaimAutomationError(
            "Services directory missing; cannot determine staking configuration."
        )

    for service_dir in services_dir.iterdir():
        config_path = service_dir / "config.json"
        if not config_path.exists():
            continue

        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logging.warning("Skipping malformed service config at %s", config_path)
            continue

        chain_configs = config.get("chain_configs", {})
        for chain_name, chain_config in chain_configs.items():
            chain_data = chain_config.get("chain_data", {})
            user_params = chain_data.get("user_params", {})
            if not user_params.get("use_staking"):
                continue

            rpc_url = chain_config.get("ledger_config", {}).get("rpc")
            staking_contract = user_params.get("staking_program_id")
            service_id = chain_data.get("token")
            keys = config.get("keys", [])
            operator_key = next(
                (
                    key.get("private_key")
                    for key in keys
                    if key.get("ledger") == "ethereum" and key.get("private_key")
                ),
                None,
            )

            if not rpc_url:
                raise ClaimAutomationError(
                    "Missing RPC URL for staking chain in service configuration."
                )
            if not staking_contract:
                raise ClaimAutomationError(
                    "Missing staking contract address in service configuration."
                )
            if service_id is None:
                raise ClaimAutomationError(
                    "Missing service ID (token) in staking chain configuration."
                )
            if not operator_key:
                raise ClaimAutomationError(
                    "Ethereum private key not found in service configuration keys."
                )

            return StakingContext(
                chain_name=chain_name,
                rpc_url=rpc_url,
                staking_contract=staking_contract,
                service_id=int(service_id),
                operator_private_key=operator_key,
                service_multisig=chain_data.get("multisig"),
            )

    raise ClaimAutomationError(
        "Unable to locate a service configuration with staking enabled."
    )


def load_staking_token_abi() -> list:
    """Load the staking token ABI from disk."""

    try:
        staking_token_data = json.loads(
            STAKING_TOKEN_JSON_PATH.read_text(encoding="utf-8")
        )
    except FileNotFoundError as exc:  # pragma: no cover - configuration error
        raise ClaimAutomationError(
            f"StakingToken ABI missing at {STAKING_TOKEN_JSON_PATH}"
        ) from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - configuration error
        raise ClaimAutomationError("StakingToken ABI file is not valid JSON.") from exc

    abi = staking_token_data.get("abi")
    if not isinstance(abi, list):
        raise ClaimAutomationError("StakingToken ABI missing 'abi' array.")
    return abi


def setup_web3(rpc_url: str) -> Web3:
    """Create a Web3 connection with sensible middleware for Base."""

    provider = HTTPProvider(rpc_url)
    w3 = Web3(provider)
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    if not w3.is_connected():
        raise ClaimAutomationError(
            f"Could not establish Web3 connection to RPC endpoint {rpc_url}"
        )
    return w3


def format_reward_olas(reward_wei: int) -> str:
    """Pretty-print rewards in OLAS units."""

    olas_amount = Web3.from_wei(reward_wei, "ether")
    return f"{olas_amount:.6f} OLAS"


def build_safe_signature(message_hash: HexBytes, private_key: str) -> bytes:
    """Sign the Safe transaction hash and return the Safe-formatted signature bytes."""

    signed = Account.sign_hash(message_hash, private_key=private_key)
    v_value = signed.v
    if v_value >= 27:
        v_value -= 27

    return (
        signed.r.to_bytes(32, byteorder="big")
        + signed.s.to_bytes(32, byteorder="big")
        + v_value.to_bytes(1, byteorder="big")
    )


def attempt_claim(*, dry_run: bool = False) -> Optional[str]:
    """Run a single claim attempt; returns transaction hash if submitted."""

    context = find_staking_context()
    wallet_safe = load_wallet_safe(context.chain_name)

    staking_abi = load_staking_token_abi()
    w3 = setup_web3(context.rpc_url)

    staking_contract = w3.eth.contract(
        address=checksum(context.staking_contract), abi=staking_abi
    )

    service_info = staking_contract.functions.mapServiceInfo(context.service_id).call()
    reward_due = int(service_info[3])

    logging.info(
        "Service %s rewards available: %s",
        context.service_id,
        format_reward_olas(reward_due),
    )

    if reward_due <= 0:
        logging.info("No rewards to claim at this time; skipping Safe transaction.")
        return None

    wallet_safe_checksum = checksum(wallet_safe)
    if (
        context.service_multisig
        and checksum(context.service_multisig) != wallet_safe_checksum
    ):
        logging.warning(
            "Service config multisig %s differs from wallet Safe %s; proceeding with wallet Safe per instruction.",
            context.service_multisig,
            wallet_safe_checksum,
        )

    if not w3.eth.get_code(wallet_safe_checksum):
        raise ClaimAutomationError(
            f"Address {wallet_safe_checksum} has no contract code; cannot execute Safe transaction."
        )

    safe_contract = w3.eth.contract(address=wallet_safe_checksum, abi=SAFE_ABI)
    safe_nonce = safe_contract.functions.nonce().call()
    logging.info("Safe nonce before claim attempt: %s", safe_nonce)

    claim_calldata = staking_contract.encodeABI(
        fn_name="claim", args=[context.service_id]
    )

    safe_tx_hash = safe_contract.functions.getTransactionHash(
        checksum(context.staking_contract),
        0,
        HexBytes(claim_calldata),
        0,
        0,
        0,
        0,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        safe_nonce,
    ).call()

    signature_bytes = build_safe_signature(
        HexBytes(safe_tx_hash), context.operator_private_key
    )

    if dry_run:
        logging.info("Dry-run enabled; skipping execTransaction submission.")
        return None

    operator_account = Account.from_key(context.operator_private_key)
    exec_tx = safe_contract.functions.execTransaction(
        checksum(context.staking_contract),
        0,
        HexBytes(claim_calldata),
        0,
        0,
        0,
        0,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        signature_bytes,
    )

    tx_params = {
        "from": operator_account.address,
        "nonce": w3.eth.get_transaction_count(operator_account.address),
        "value": 0,
    }

    try:
        gas_estimate = exec_tx.estimate_gas(tx_params)
    except ContractLogicError as exc:
        raise ClaimAutomationError(
            f"Safe execTransaction gas estimation failed: {exc.args[0]}"
        ) from exc

    gas_limit = int(gas_estimate * 1.2) + 1000
    gas_price = w3.eth.gas_price

    tx_payload = exec_tx.build_transaction(
        {
            **tx_params,
            "gas": gas_limit,
            "gasPrice": int(gas_price * 12 // 10),
            "chainId": w3.eth.chain_id,
        }
    )

    signed_tx = operator_account.sign_transaction(tx_payload)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    logging.info("Submitted claim transaction %s", tx_hash.hex())

    return tx_hash.hex()


def run(interval_seconds: int, *, dry_run: bool, once: bool) -> None:
    """Execute the claim loop."""

    while True:
        start_time = time.time()
        try:
            attempt_claim(dry_run=dry_run)
        except ClaimAutomationError:
            logging.exception(
                "Claim attempt aborted due to configuration/runtime error."
            )
        except Exception:  # pragma: no cover - defensive logging
            logging.exception("Unexpected error during claim attempt.")

        if once:
            break

        elapsed = time.time() - start_time
        sleep_duration = max(interval_seconds - elapsed, 0)
        if sleep_duration:
            logging.info("Sleeping %.0f seconds before next attempt.", sleep_duration)
            time.sleep(sleep_duration)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Monitor staking rewards and trigger Safe-based claim transactions when rewards are available."
        )
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Polling interval in seconds between claim attempts (default: 3600)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single claim attempt and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not submit transactions; useful for validation.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO)",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the claim automation script."""

    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    run(args.interval, dry_run=args.dry_run, once=args.once)


if __name__ == "__main__":  # pragma: no cover - script entry point
    main()

