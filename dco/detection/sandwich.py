"""
sandwich.py — Detect sandwich MEV attacks from Uniswap V2/V3 Swap events.

A valid sandwich triplet (f, v, b) satisfies all of:
  1. f and b interact with the SAME pool
  2. f and b come from the same beneficial owner (attacker)
  3. v is from a DIFFERENT user
  4. f and b are in OPPOSITE swap directions (token0->token1 vs token1->token0)
  5. v appears between f and b in block order (tx_index: f < v < b)
"""

from data.rpc_client import w3

# Uniswap V2: Swap(address indexed sender, uint256 amount0In, uint256 amount1In,
#                   uint256 amount0Out, uint256 amount1Out, address indexed to)

V2_SWAP_TOPIC = w3.keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)").hex()

# Uniswap V3: Swap(address indexed sender, address indexed recipient,
#                   int256 amount0, int256 amount1, uint160 sqrtPriceX96,
#                   uint128 liquidity, int24 tick)

V3_SWAP_TOPIC = w3.keccak(
    text="Swap(address,address,int256,int256,uint160,uint128,int24)").hex()

# Known router addresses. When a Swap event's 'to'/'recipient' is one of these,
# it's not the real beneficial owner (just the router forwarding tokens onward) —
# fall back to tx.from instead.


ROUTERS = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router02
    "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 SwapRouter
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap V3 SwapRouter02
}


def _decode_v2_swap(log: dict) -> dict:
    """
    Decode a raw Uniswap V2 Swap log.

    Non-indexed data layout (4 x uint256): amount0In | amount1In | amount0Out | amount1Out
    Indexed topics: topics[1] = sender, topics[2] = to
    """
    data = bytes.fromhex(
        log["data"].hex() if isinstance(log["data"], bytes) else log["data"].lstrip("0x")
    )
    amount0_in = int.from_bytes(data[0:32], "big") #big-endian integer
    amount1_in = int.from_bytes(data[32:64], "big")
    amount0_out = int.from_bytes(data[64:96], "big")
    amount1_out = int.from_bytes(data[96:128], "big")

    if amount0_in > 0 and amount1_out > 0:
        direction = "0to1"  # sold token0, bought token1
        amount_in, amount_out = amount0_in, amount1_out
    else:
        direction = "1to0"  # sold token1, bought token0
        amount_in, amount_out = amount1_in, amount0_out

    to_addr = "0x" + log["topics"][2].hex()[-40:] #get the last 20 bytes of the address from the topics[2] which is the 'to' address

    return {
        "version": "v2",
        "direction": direction,
        "amount_in": amount_in,
        "amount_out": amount_out,
        "to": to_addr.lower(),
    }


def _decode_v3_swap(log: dict) -> dict:
    """
    Decode a raw Uniswap V3 Swap log.

    Non-indexed data layout: int256 amount0 | int256 amount1 | uint160 sqrtPriceX96 |
                              uint128 liquidity | int24 tick
    Indexed topics: topics[1] = sender, topics[2] = recipient
    Negative amount = tokens left the pool (pool paid out); positive = tokens entered the pool.
    """
    data = bytes.fromhex(
        log["data"].hex() if isinstance(log["data"], bytes) else log["data"].lstrip("0x")
    )

    # standard two's complement decoding 
    def to_signed(b: bytes) -> int:
        v = int.from_bytes(b, "big")
        return v - (1 << 256) if v >= (1 << 255) else v

    amount0 = to_signed(data[0:32])
    amount1 = to_signed(data[32:64])

    if amount0 < 0:
        direction = "1to0"  # token0 left the pool -> user paid token1, received token0
        amount_in, amount_out = amount1, abs(amount0)
    else:
        direction = "0to1"
        amount_in, amount_out = amount0, abs(amount1)

    recipient = "0x" + log["topics"][2].hex()[-40:] #get the last 20 bytes of the address from the topics[2] which is the 'recipient' address

    return {
        "version": "v3",
        "direction": direction,
        "amount_in": amount_in,
        "amount_out": amount_out,
        "to": recipient.lower(),
    }


def get_swap_events_in_block(block_number: int) -> list[dict]:
    """
    Fetch and decode all Uniswap V2 and V3 Swap events in a block.

    Returns a list of dicts, each with: tx_hash, tx_index, log_index, pool_address,
    version, direction, amount_in, amount_out, to (beneficial recipient per the event),
    tx_from (msg.sender of the transaction -- may be a router, not the real trader).
    """
    logs_v2 = w3.eth.get_logs(
        {"fromBlock": block_number, "toBlock": block_number, "topics": [V2_SWAP_TOPIC]}
    )
    logs_v3 = w3.eth.get_logs(
        {"fromBlock": block_number, "toBlock": block_number, "topics": [V3_SWAP_TOPIC]}
    )

    # tx.from isn't in the log itself, so fetch it once per unique tx and cache it.
    all_logs = list(logs_v2) + list(logs_v3)
    tx_from_cache: dict[str, str] = {}
    for log in all_logs:
        tx_hash = log["transactionHash"].hex()
        if tx_hash not in tx_from_cache:
            tx = w3.eth.get_transaction(tx_hash)
            tx_from_cache[tx_hash] = tx["from"].lower()

    swaps = []
    for log in logs_v2:
        try:
            decoded = _decode_v2_swap(log)
        except Exception:
            continue
        tx_hash = log["transactionHash"].hex()
        swaps.append(
            {
                "tx_hash": tx_hash,
                "tx_index": log["transactionIndex"],
                "log_index": log["logIndex"],
                "pool_address": log["address"].lower(),
                "tx_from": tx_from_cache[tx_hash],
                **decoded,
            }
        )

    for log in logs_v3:
        if len(log["topics"]) < 3:
            continue
        try:
            decoded = _decode_v3_swap(log)
        except Exception:
            continue
        tx_hash = log["transactionHash"].hex()
        swaps.append(
            {
                "tx_hash": tx_hash,
                "tx_index": log["transactionIndex"],
                "log_index": log["logIndex"],
                "pool_address": log["address"].lower(),
                "tx_from": tx_from_cache[tx_hash],
                **decoded,
            }
        )

    return swaps


def _owner(swap: dict) -> str:
    """
    The beneficial owner of a swap: the 'to'/'recipient' address from the event,
    unless that's a known router (in which case it's just forwarding tokens onward,
    so fall back to tx_from -- the actual account that signed the transaction).
    """
    to = swap["to"]
    if to in ROUTERS or to == swap["pool_address"]:
        return swap["tx_from"]
    return to


def _opposite(direction: str) -> str:
    return "1to0" if direction == "0to1" else "0to1"


def detect_sandwiches(block_number: int, swaps: list[dict]) -> list[dict]:
    """
    Find sandwich triplets (f, v, b) among swaps in the same block.

    For each pool, swaps are sorted by their position in the block, then every
    (f, v, b) combination is checked against the 5 conditions listed at the top
    of this file. Each frontrun tx is used in at most one triplet.
    """
    by_pool: dict[str, list[dict]] = {}
    for s in swaps:
        by_pool.setdefault(s["pool_address"], []).append(s)

    triplets = []
    for pool, events in by_pool.items():
        if len(events) < 3:
            continue
        events.sort(key=lambda e: (e["tx_index"], e["log_index"]))  #orders swaps exactly as they appear in the block 
        

        used_as_frontrun = set()

        for i in range(len(events) - 2):
            f = events[i]
            if f["tx_hash"] in used_as_frontrun:
                continue
            owner_f = _owner(f)

            for j in range(i + 1, len(events) - 1):
                v = events[j]
                if v["tx_hash"] == f["tx_hash"]:
                    continue
                owner_v = _owner(v)
                if owner_v == owner_f:
                    continue  # victim must be a different owner than the frontrunner

                found_backrun = False
                for k in range(j + 1, len(events)):
                    b = events[k]
                    if b["tx_hash"] in (f["tx_hash"], v["tx_hash"]):
                        continue
                    owner_b = _owner(b)

                    if owner_b == owner_f and b["direction"] == _opposite(f["direction"]):
                        triplets.append(
                            {
                                "mev_type": "sandwich",
                                "block_number": block_number,
                                "pool_address": pool,
                                "pool_version": f["version"],
                                "attacker_address": owner_f,
                                "victim_address": owner_v,
                                "frontrun_tx": f["tx_hash"],
                                "frontrun_tx_index": f["tx_index"],
                                "frontrun_direction": f["direction"],
                                "frontrun_amount_in": f["amount_in"],
                                "frontrun_amount_out": f["amount_out"],
                                "victim_tx": v["tx_hash"],
                                "victim_tx_index": v["tx_index"],
                                "victim_direction": v["direction"],
                                "victim_amount_in": v["amount_in"],
                                "victim_amount_out": v["amount_out"],
                                "backrun_tx": b["tx_hash"],
                                "backrun_tx_index": b["tx_index"],
                                "backrun_direction": b["direction"],
                                "backrun_amount_in": b["amount_in"],
                                "backrun_amount_out": b["amount_out"],
                            }
                        )
                        used_as_frontrun.add(f["tx_hash"])
                        found_backrun = True
                        break  # only the first matching backrun per (f, v) pair

                if found_backrun:
                    break  # only one victim per frontrun

    return triplets
