"""
rpc_client.py — Single shared connection to an Ethereum node via Alchemy.

Every other module that needs chain data (get_logs, get_transaction, get_block, ...)
imports `w3` from here instead of constructing its own connection.
"""

import os
import sys

from dotenv import load_dotenv
from web3 import Web3

# load_dotenv() reads .env
load_dotenv()

ALCHEMY_RPC_URL = os.getenv("ALCHEMY_RPC_URL")
if not ALCHEMY_RPC_URL:
    print("ERROR: Set ALCHEMY_RPC_URL in .env (see .env.example)")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(ALCHEMY_RPC_URL))
assert w3.is_connected(), "Cannot connect to Alchemy RPC"
