#!/usr/bin/env python3
"""Generate checkpoints.json (mainnet or testnet) from a Blackcoin Core RPC node
(and optionally cross-verify against local blockchain_headers).

Stores the block hash at the end of every 2016-block chunk ((index + 1) * 2016 - 1),
plus historical protocol transition milestone heights, stopping at least MAX_REORG_DEPTH
blocks before the current chain tip.
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from electrum_blk import blockchain, constants

CHUNK_SIZE = blockchain.CHUNK_SIZE  # 2016
MAINNET_MILESTONES = [
    5001,
    10000,
    38425,
    254348,
    319002,
    872456,
    4232630,
    4908715,
    5805000,
    5930110,
]
TESTNET_MILESTONES = [
    90235,
    1320664,
    1415393,
    2070000,
    2865000,
]


def rpc_call(url: str, user: str, password: str, payload):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "text/plain;",
            "Authorization": f"Basic {auth}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def generate_for_network(*, testnet: bool, rpc_url: str, rpc_user: str, rpc_password: str, headers_file: str, output: str):
    net = constants.BitcoinTestnet if testnet else constants.BitcoinMainnet
    milestones = TESTNET_MILESTONES if testnet else MAINNET_MILESTONES

    info_resp = rpc_call(
        rpc_url,
        rpc_user,
        rpc_password,
        {"jsonrpc": "1.0", "id": "info", "method": "getblockchaininfo", "params": []},
    )
    blocks = info_resp["result"]["blocks"]
    safe_height = blocks - net.MAX_REORG_DEPTH
    num_chunks = safe_height // CHUNK_SIZE
    max_cp_height = num_chunks * CHUNK_SIZE - 1
    print(f"[{net.NET_NAME}] RPC chain tip: {blocks}, generating {num_chunks} chunk checkpoints up to height {max_cp_height}...")

    heights = sorted(
        set(((i + 1) * CHUNK_SIZE - 1 for i in range(num_chunks)))
        | {h for h in milestones if h <= max_cp_height}
    )

    checkpoints = {}
    batch_size = 500
    for start in range(0, len(heights), batch_size):
        batch_heights = heights[start : start + batch_size]
        payload = [
            {"jsonrpc": "1.0", "id": h, "method": "getblockhash", "params": [h]}
            for h in batch_heights
        ]
        responses = rpc_call(rpc_url, rpc_user, rpc_password, payload)
        for item in responses:
            if item.get("error"):
                raise RuntimeError(f"RPC error for height {item.get('id')}: {item['error']}")
            checkpoints[str(item["id"])] = item["result"]

    headers_path = Path(headers_file)
    if headers_path.exists():
        data = headers_path.read_bytes()
        local_num_headers = len(data) // 80
        verified = 0
        for h_str, rpc_hash in checkpoints.items():
            h = int(h_str)
            if h < local_num_headers:
                raw = data[h * 80 : (h + 1) * 80]
                if any(raw):
                    hdr = blockchain.deserialize_header(raw, h)
                    local_hash = blockchain.hash_header(hdr)
                    if local_hash != rpc_hash:
                        raise RuntimeError(f"Hash mismatch at height {h}: local={local_hash} != rpc={rpc_hash}")
                    verified += 1
        print(f"[{net.NET_NAME}] Cross-verified {verified}/{len(checkpoints)} checkpoints against {headers_path}")

    ordered = {str(h): checkpoints[str(h)] for h in heights}
    out_path = Path(output)
    out_path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
    print(f"[{net.NET_NAME}] Wrote {len(ordered)} checkpoints (max height {max_cp_height}) to {out_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate Blackcoin checkpoints.json")
    parser.add_argument("--testnet", action="store_true", help="Generate testnet checkpoints (default port 25715)")
    parser.add_argument("--rpc-url", default=None)
    parser.add_argument("--rpc-user", default=os.environ.get("BLK_RPC_USER", "blackcoin"))
    parser.add_argument("--rpc-password", default=os.environ.get("BLK_RPC_PASSWORD", "blackcoin"))
    parser.add_argument("--headers-file", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)

    default_port = 25715 if args.testnet else 15715
    chain_name = "testnet" if args.testnet else "mainnet"
    rpc_url = args.rpc_url or os.environ.get("BLK_RPC_URL", f"http://192.168.0.207:{default_port}/")
    headers_file = args.headers_file or str(
        (Path.home() / ".electrum-blk" / "testnet" / "blockchain_headers")
        if args.testnet
        else (Path.home() / ".electrum-blk" / "blockchain_headers")
    )
    output = args.output or str(REPO_ROOT / "electrum_blk" / "chains" / chain_name / "checkpoints.json")

    generate_for_network(
        testnet=args.testnet,
        rpc_url=rpc_url,
        rpc_user=args.rpc_user,
        rpc_password=args.rpc_password,
        headers_file=headers_file,
        output=output,
    )


if __name__ == "__main__":
    main()
