#!/usr/bin/env python3
"""Generate electrum_blk/chains/mainnet/checkpoints.json from a Blackcoin Core RPC node
(and optionally cross-verify against local ~/.electrum-blk/blockchain_headers).

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
MILESTONE_HEIGHTS = [
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


def main():
    parser = argparse.ArgumentParser(description="Generate Blackcoin checkpoints.json")
    parser.add_argument("--rpc-url", default=os.environ.get("BLK_RPC_URL", "http://192.168.0.207:15715/"))
    parser.add_argument("--rpc-user", default=os.environ.get("BLK_RPC_USER", "blackcoin"))
    parser.add_argument("--rpc-password", default=os.environ.get("BLK_RPC_PASSWORD", "blackcoin"))
    parser.add_argument(
        "--headers-file",
        default=str(Path.home() / ".electrum-blk" / "blockchain_headers"),
        help="Optional local blockchain_headers file to cross-verify against",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "electrum_blk" / "chains" / "mainnet" / "checkpoints.json"),
    )
    args = parser.parse_args()

    info_resp = rpc_call(
        args.rpc_url,
        args.rpc_user,
        args.rpc_password,
        {"jsonrpc": "1.0", "id": "info", "method": "getblockchaininfo", "params": []},
    )
    blocks = info_resp["result"]["blocks"]
    safe_height = blocks - constants.BitcoinMainnet.MAX_REORG_DEPTH
    num_chunks = safe_height // CHUNK_SIZE
    max_cp_height = num_chunks * CHUNK_SIZE - 1
    print(f"RPC chain tip: {blocks}, generating {num_chunks} chunk checkpoints up to height {max_cp_height}...")

    heights = sorted(
        set(((i + 1) * CHUNK_SIZE - 1 for i in range(num_chunks)))
        | {h for h in MILESTONE_HEIGHTS if h <= max_cp_height}
    )

    checkpoints = {}
    batch_size = 500
    for start in range(0, len(heights), batch_size):
        batch_heights = heights[start : start + batch_size]
        payload = [
            {"jsonrpc": "1.0", "id": h, "method": "getblockhash", "params": [h]}
            for h in batch_heights
        ]
        responses = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password, payload)
        for item in responses:
            if item.get("error"):
                raise RuntimeError(f"RPC error for height {item.get('id')}: {item['error']}")
            checkpoints[str(item["id"])] = item["result"]

    # Cross-verify against local blockchain_headers if present
    headers_path = Path(args.headers_file)
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
        print(f"Cross-verified {verified}/{len(checkpoints)} checkpoints against {headers_path}")

    # Sort keys numerically
    ordered = {str(h): checkpoints[str(h)] for h in heights}
    out_path = Path(args.output)
    out_path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(ordered)} checkpoints (max height {max_cp_height}) to {out_path}")


if __name__ == "__main__":
    main()
