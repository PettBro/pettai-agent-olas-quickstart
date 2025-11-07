# staking_report.py
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
import json
import math
from pathlib import Path
from web3 import Web3, HTTPProvider
from decimal import Decimal, getcontext
import logging
from datetime import datetime, timezone
from custom_types import ChainType

OPERATE_HOME = Path.cwd() / ".operate"


STAKING = {
    ChainType.BASE: {"pett_ai": "0x31183503be52391844594b4B587F0e764eB3956E"},
}

from utils import (
    _print_section_header,
    _print_subsection_header,
    _print_status,
    wei_to_olas,
    wei_to_eth,
    _warning_message,
    StakingState,
    get_chain_name,
    load_operator_address,
    load_operator_safe_balance,
    validate_config,
    _color_bool,
    _color_string,
    ColorCode,
)

# Set decimal precision
getcontext().prec = 18

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

SCRIPT_PATH = Path(__file__).resolve().parent
STAKING_TOKEN_JSON_PATH = SCRIPT_PATH / "contracts" / "StakingToken.json"
ACTIVITY_CHECKER_JSON_PATH = SCRIPT_PATH / "contracts" / "PetActivityChecker.json"
SERVICE_REGISTRY_TOKEN_UTILITY_JSON_PATH = (
    SCRIPT_PATH / "contracts" / "ServiceRegistryTokenUtility.json"
)


def staking_report(config: dict) -> None:
    try:
        _print_section_header("Performance")
        home_chain = config.get("principal_chain", "base")
        rpc = config.get("rpc", {}).get(home_chain)
        if not rpc:
            print("Error: RPC endpoint not found in quickstart config.")
            return

        w3_perf = Web3(HTTPProvider(rpc))

        # Basic network metrics
        try:
            chain_id = w3_perf.eth.chain_id
            latest_block = w3_perf.eth.block_number
            gas_price_wei = w3_perf.eth.gas_price
            latest_block_obj = w3_perf.eth.get_block("latest")
            base_fee_wei = latest_block_obj.get("baseFeePerGas")

            _print_status("Network", str(home_chain))
            _print_status("Chain ID", str(chain_id))
            _print_status("Latest block", str(latest_block))
            _print_status(
                "Gas price", f"{Decimal(gas_price_wei) / Decimal(1e9):.1f} gwei"
            )
            if base_fee_wei is not None:
                _print_status(
                    "Base fee", f"{Decimal(base_fee_wei) / Decimal(1e9):.1f} gwei"
                )
        except Exception:
            pass

        # SAFE balance
        try:
            safe_balance_wei = load_operator_safe_balance(OPERATE_HOME)
            if safe_balance_wei is not None:
                _print_status("SAFE balance", f"{wei_to_eth(safe_balance_wei):.4f} ETH")
        except Exception:
            pass

        # Find the chain configuration where use_staking is True
        chain_data = None

        # Search through all service folders
        services_dir = OPERATE_HOME / "services"
        if services_dir.exists():
            for service_folder in services_dir.iterdir():
                if service_folder.is_dir():
                    config_path = service_folder / "config.json"
                    if config_path.exists():
                        try:
                            with open(config_path, "r") as f:
                                service_config = json.load(f)

                            logging.info(
                                f"Inspecting service folder: {service_folder.name}"
                            )
                            logging.info(
                                f"Available chains: {list(service_config.get('chain_configs', {}).keys())}"
                            )

                            # Search through chain_configs for use_staking = True
                            chain_configs = service_config.get("chain_configs", {})
                            for chain_name, chain_config in chain_configs.items():
                                user_params = chain_config.get("chain_data", {}).get(
                                    "user_params", {}
                                )
                                if user_params.get("use_staking", False):
                                    logging.info(
                                        f"Selected chain '{chain_name}' with use_staking=True"
                                    )
                                    chain_data = chain_config
                                    break

                            if chain_data:
                                break
                        except (json.JSONDecodeError, KeyError):
                            continue

        if not chain_data:
            print("Error: Chain data not found in config.")
            return

        _print_subsection_header("Staking")
        logging.info(
            "Selected chain_data summary: "
            + json.dumps(
                {
                    "ledger_rpc": chain_data.get("ledger_config", {}).get("rpc"),
                    "token": chain_data.get("chain_data", {}).get("token"),
                    "multisig": chain_data.get("chain_data", {}).get("multisig"),
                    "user_params": chain_data.get("chain_data", {}).get(
                        "user_params", {}
                    ),
                },
                default=str,
            )
        )
        rpc = chain_data.get("ledger_config", {}).get("rpc")
        if not rpc:
            print("Error: RPC endpoint not found in ledger configuration.")
            return

        staking_program_id = (
            chain_data.get("chain_data", {})
            .get("user_params", {})
            .get("staking_program_id")
        )
        if not staking_program_id:
            print("Error: 'staking_program_id' not found in user parameters.")
            return

        # get from principal_chain do it by connecting base -> 8453
        home_chain = config.get("principal_chain")
        if not home_chain:
            print("Error: 'home_chain' not found in config.")
            return

        service_id = chain_data.get("chain_data", {}).get("token")
        if not service_id:
            print(f"Error: 'token' not found in chain data for chain ID {home_chain}.")
            return

        multisig_address = chain_data.get("chain_data", {}).get("multisig")
        if not multisig_address:
            print(
                f"Error: 'multisig' address not found in chain data for chain ID {home_chain}."
            )
            return

        w3 = Web3(HTTPProvider(rpc))

        # Load operator address for staking queries
        operator_address = load_operator_address(OPERATE_HOME)
        if not operator_address:
            print("Error: Operator address could not be loaded.")
            return

        home_chain_type = ChainType.from_string(home_chain)
        staking_token_address = STAKING.get(home_chain_type, {}).get("pett_ai")
        if not staking_token_address:
            print(
                f"Error: Staking token address not found for ChainType {home_chain_type}."
            )
            return

        logging.info(
            f"Using staking token address: {staking_token_address} on chain {home_chain_type}"
        )

        # Load ABI files
        with open(STAKING_TOKEN_JSON_PATH, "r", encoding="utf-8") as file:
            staking_token_data = json.load(file)
        staking_token_abi = staking_token_data.get("abi", [])
        staking_token_contract = w3.eth.contract(
            address=staking_token_address, abi=staking_token_abi  # type: ignore
        )

        # Get staking state
        staking_state_value = staking_token_contract.functions.getStakingState(
            service_id
        ).call()
        staking_state = StakingState(staking_state_value)
        is_staked = staking_state in (StakingState.STAKED, StakingState.EVICTED)
        _print_status("Is service staked?", _color_bool(is_staked, "Yes", "No"))
        if is_staked:
            # Epoch schedule and checkpoint status
            try:
                next_cp_ts = (
                    staking_token_contract.functions.getNextRewardCheckpointTimestamp().call()
                )
                now_ts = int(datetime.now(timezone.utc).timestamp())
                seconds_delta = next_cp_ts - now_ts
                next_cp_iso = datetime.fromtimestamp(
                    next_cp_ts, tz=timezone.utc
                ).isoformat()
                _print_status("Epoch ends", next_cp_iso)
                abs_delta = abs(int(seconds_delta))
                hours, rem = divmod(abs_delta, 3600)
                minutes, seconds = divmod(rem, 60)
                when_text = (
                    f"in {hours}h {minutes}m {seconds}s"
                    if seconds_delta > 0
                    else f"ended {hours}h {minutes}m {seconds}s ago"
                )
                _print_status("Time to epoch end", when_text)

                if seconds_delta < 0:
                    print(
                        "Checkpoint has not being called yet for the previous epoch.",
                    )
            except Exception:
                pass
            _print_status(
                "Staking program",
                (
                    str(staking_program_id)
                    + " "
                    + str(home_chain_type).rsplit(".", maxsplit=1)[-1]
                ),
            )
            _print_status(
                "Staking state",
                (
                    staking_state.name
                    if staking_state == StakingState.STAKED
                    else _color_string(staking_state.name, ColorCode.RED)
                ),
            )

            # Activity Checker
            activity_checker_address = (
                staking_token_contract.functions.activityChecker().call()
            )
            with open(ACTIVITY_CHECKER_JSON_PATH, "r", encoding="utf-8") as file:
                activity_checker_data = json.load(file)
            activity_checker_abi = activity_checker_data.get("abi", [])
            activity_checker_contract = w3.eth.contract(
                address=activity_checker_address, abi=activity_checker_abi  # type: ignore
            )

            # Service Registry Token Utility
            with open(
                SERVICE_REGISTRY_TOKEN_UTILITY_JSON_PATH, "r", encoding="utf-8"
            ) as file:
                service_registry_token_utility_data = json.load(file)
            service_registry_token_utility_contract_address = (
                staking_token_contract.functions.serviceRegistryTokenUtility().call()
            )
            logging.info(
                f"ServiceRegistryTokenUtility at {service_registry_token_utility_contract_address}"
            )
            service_registry_token_utility_abi = (
                service_registry_token_utility_data.get("abi", [])
            )

            service_registry_token_utility_contract = w3.eth.contract(
                address=service_registry_token_utility_contract_address,
                abi=service_registry_token_utility_abi,
            )

            print("Current operator address", operator_address)

            # Get security deposit
            security_deposit = (
                service_registry_token_utility_contract.functions.getOperatorBalance(
                    operator_address, service_id
                ).call()
            )

            # Get agent bond (read agent_id from chain_data user_params)
            agent_id = (
                chain_data.get("chain_data", {}).get("user_params", {}).get("agent_id")
            )
            logging.info(f"Resolved agent_id from chain_data: {agent_id}")
            if agent_id is None:
                print("Error: 'agent_id' not found in user parameters.")
                return

            # Accrued rewards
            service_info = staking_token_contract.functions.mapServiceInfo(
                service_id
            ).call()
            rewards = service_info[3]
            _print_status("Accrued rewards", wei_to_olas(rewards))

            # Liveness ratio and transactions
            liveness_ratio = activity_checker_contract.functions.livenessRatio().call()
            multisig_nonces_24h_threshold = math.ceil(
                (liveness_ratio * 60 * 60 * 24) / Decimal(1e18)
            )

            multisig_nonces_raw = activity_checker_contract.functions.getMultisigNonces(
                multisig_address
            ).call()
            if isinstance(multisig_nonces_raw, (list, tuple)):
                if len(multisig_nonces_raw) == 0:
                    print("Error: Empty multisig nonces returned by activity checker.")
                    return
                multisig_nonces = multisig_nonces_raw[0]
            else:
                multisig_nonces = int(multisig_nonces_raw)
            service_info = staking_token_contract.functions.getServiceInfo(
                service_id
            ).call()
            multisig_nonces_on_last_checkpoint = service_info[2][0]
            multisig_nonces_since_last_cp = (
                multisig_nonces - multisig_nonces_on_last_checkpoint
            )
            multisig_nonces_current_epoch = multisig_nonces_since_last_cp
            _print_status(
                f"txs in current epoch: ",
                str(multisig_nonces_current_epoch),
                _warning_message(
                    Decimal(multisig_nonces_current_epoch),
                    Decimal(multisig_nonces_24h_threshold),
                    f"- Too low. Threshold is {multisig_nonces_24h_threshold}.",
                ),
            )
            try:
                to_go = max(
                    int(multisig_nonces_24h_threshold)
                    - int(multisig_nonces_current_epoch),
                    0,
                )
                _print_status(
                    "Required txs this epoch", str(int(multisig_nonces_24h_threshold))
                )
                _print_status("Txs remaining", str(to_go))
            except Exception:
                pass

    except Exception as e:
        print(f"An unexpected error occurred in staking_report: {e}")


def load_config():
    """Load configuration from operate config."""
    config_path = OPERATE_HOME / "pett_agent-quickstart-config.json"
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file not found at {config_path}")
        return None
    except json.JSONDecodeError:
        print("Error: Config file contains invalid JSON.")
        return None


if __name__ == "__main__":
    try:
        # Load configuration
        config = load_config()
        if not config:
            print("Error: Config is empty.")
        else:
            staking_report(config)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
