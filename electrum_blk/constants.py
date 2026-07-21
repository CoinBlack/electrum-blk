# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import copy
import os
import json
from typing import Sequence, Tuple, Mapping, Type, List, Optional

from .lntransport import LNPeerAddr
from .util import inv_dict, all_subclasses, classproperty
from . import bitcoin


def read_json(filename, default=None):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except Exception:
        if default is None:
            # Sometimes it's better to hard-fail: the file might be missing
            # due to a packaging issue, which might otherwise go unnoticed.
            raise
        r = default
    return r


def create_fallback_node_list(fallback_nodes_dict: dict[str, dict]) -> List[LNPeerAddr]:
    """Take a json dict of fallback nodes like: k:node_id, v:{k:'host', k:'port'} and return LNPeerAddr list"""
    fallback_nodes = []
    for node_id, address in fallback_nodes_dict.items():
        fallback_nodes.append(
            LNPeerAddr(host=address['host'], port=int(address['port']), pubkey=bytes.fromhex(node_id)))
    return fallback_nodes


GIT_REPO_URL = "https://github.com/CoinBlack/electrum-blk"
GIT_REPO_ISSUES_URL = "https://github.com/CoinBlack/electrum-blk/issues"
RELEASE_NOTES_URL = "https://raw.githubusercontent.com/CoinBlack/electrum-blk/refs/heads/master/RELEASE-NOTES"
BIP39_WALLET_FORMATS = read_json('bip39_wallet_formats.json')


class AbstractNet:

    NET_NAME: str
    TESTNET: bool
    WIF_PREFIX: int
    ADDRTYPE_P2PKH: int
    ADDRTYPE_P2SH: int
    SEGWIT_HRP: str
    BOLT11_HRP: str
    GENESIS: str
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS: int = 0
    BIP44_COIN_TYPE: int
    LN_REALM_BYTE: int
    DEFAULT_PORTS: Mapping[str, str]
    LN_DNS_SEEDS: Sequence[str]
    XPRV_HEADERS: Mapping[str, int]
    XPRV_HEADERS_INV: Mapping[int, str]
    XPUB_HEADERS: Mapping[str, int]
    XPUB_HEADERS_INV: Mapping[int, str]

    @classmethod
    def max_checkpoint(cls) -> int:
        if not cls.CHECKPOINTS:
            return 0
        valid_heights = [int(k) for k, v in cls.CHECKPOINTS.items() if v and v != "0"]
        return max(valid_heights, default=0)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(cls.GENESIS)[::-1]

    @classmethod
    def set_as_network(cls) -> None:
        global net
        net = cls

    _cached_default_servers = None
    @classproperty
    def DEFAULT_SERVERS(cls) -> Mapping[str, Mapping[str, str]]:
        if cls._cached_default_servers is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            d = read_json(os.path.join('chains', cls.NET_NAME, 'servers.json'), default_file)
            # sanity check
            for k, v in d.items():
                assert isinstance(v, dict), f'value for {k} not a dict in servers.json'
                assert all(isinstance(v2, str) for v2 in v.values()), f'non-str values for key {k} in servers.json'
            cls._cached_default_servers = d
        return copy.deepcopy(cls._cached_default_servers)

    _cached_fallback_lnnodes = None
    @classproperty
    def FALLBACK_LN_NODES(cls) -> Sequence[LNPeerAddr]:
        if cls._cached_fallback_lnnodes is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            d = read_json(os.path.join('chains', cls.NET_NAME, 'fallback_lnnodes.json'), default_file)
            cls._cached_fallback_lnnodes = create_fallback_node_list(d)
        return cls._cached_fallback_lnnodes

    _cached_checkpoints = None
    @classproperty
    def CHECKPOINTS(cls) -> Mapping[str, str]:
        if cls._cached_checkpoints is None:
            try:
                cls._cached_checkpoints = read_json(os.path.join('chains', cls.NET_NAME, 'checkpoints.json'))
            except Exception as e:
                raise Exception(f"Failed to load checkpoints for {cls.NET_NAME}: {e}. "
                                f"Ensure chains/{cls.NET_NAME}/checkpoints.json exists.") from e
        return cls._cached_checkpoints

    @classmethod
    def datadir_subdir(cls) -> Optional[str]:
        """The name of the folder in the filesystem.
        None means top-level, used by mainnet.
        """
        return cls.NET_NAME

    @classmethod
    def cli_flag(cls) -> str:
        """as used in e.g. `$ run_electrum --testnet4`"""
        return cls.NET_NAME

    @classmethod
    def config_key(cls) -> str:
        """as used for SimpleConfig.get()"""
        return cls.NET_NAME


class BitcoinMainnet(AbstractNet):

    NET_NAME = "mainnet"
    TESTNET = False
    WIF_PREFIX = 0x99
    ADDRTYPE_P2PKH = 25
    ADDRTYPE_P2SH = 85
    SEGWIT_HRP = "blk"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563"
    DEFAULT_PORTS = {'t': '10001', 's': '10002'}
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 100000000
    COINBASE_MATURITY = 500
    TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 100_000_000  # 100M BLK (unlimited supply, 1% APR -- sensible upper bound for amount validation)

    POW_LIMIT = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POS_LIMIT = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POS_LIMITV2 = 0x000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff
    LAST_POW_BLOCK = 10000
    TARGET_TIMESPAN = 16 * 60
    TARGET_SPACING_V1 = 60
    TARGET_SPACING = 64
    STAKE_TIMESTAMP_MASK = 0xf
    FIRST_POSV1RF_BLOCK = 38425
    FIRST_POSV2_BLOCK = 319002
    FIRST_POSV3_BLOCK = 872456
    # Protocol version transition timestamps (from Core's nProtocolV*Time in chainparams.cpp)
    # Used for timestamp-based gating matching IsProtocolV1RetargetingFixed/V2/V3 predicates
    FIRST_POSV1RF_BLOCK_TIME = 1395631999  # nProtocolV1RetargetingFixedTime
    FIRST_POSV2_BLOCK_TIME   = 1407053625  # nProtocolV2Time
    FIRST_POSV3_BLOCK_TIME   = 1444028400  # nProtocolV3Time
    FIRST_POSV3_1_BLOCK_TIME = 1713938400  # nProtocolV3_1Time
    MAX_REORG_DEPTH = 500

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 10
    LN_REALM_BYTE = 10
    LN_DNS_SEEDS = []

    @classmethod
    def datadir_subdir(cls):
        return None


class BitcoinTestnet(AbstractNet):

    NET_NAME = "testnet"
    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tblk"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
    DEFAULT_PORTS = {'t': '10011', 's': '10012'}
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 100000000
    COINBASE_MATURITY = 10
    TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 100_000_000  # 100M BLK (unlimited supply, 1% APR -- sensible upper bound for amount validation)

    POW_LIMIT = 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POS_LIMIT = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    POS_LIMITV2 = 0x000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff
    TARGET_TIMESPAN = 16 * 60
    TARGET_SPACING_V1 = 60
    TARGET_SPACING = 64
    STAKE_TIMESTAMP_MASK = 0xf
    LAST_POW_BLOCK = 0x7fffffff
    FIRST_POSV1RF_BLOCK = 38425
    FIRST_POSV2_BLOCK = 319002
    FIRST_POSV3_BLOCK = 872456
    # Protocol version transition timestamps (from Core's nProtocolV*Time in chainparams.cpp)
    FIRST_POSV1RF_BLOCK_TIME = 1395631999  # nProtocolV1RetargetingFixedTime
    FIRST_POSV2_BLOCK_TIME   = 1407053625  # nProtocolV2Time
    FIRST_POSV3_BLOCK_TIME   = 1444028400  # nProtocolV3Time
    FIRST_POSV3_1_BLOCK_TIME = 1667779200  # nProtocolV3_1Time
    MAX_REORG_DEPTH = 500

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = []


class BitcoinRegtest(BitcoinTestnet):

    NET_NAME = "regtest"
    SEGWIT_HRP = "blrt"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
    LAST_POW_BLOCK = 0x7fffffff
    FIRST_POSV3_1_BLOCK_TIME = 1713938400
    LN_DNS_SEEDS = []


NETS_LIST = tuple(all_subclasses(AbstractNet))  # type: Sequence[Type[AbstractNet]]
NETS_LIST = tuple(sorted(NETS_LIST, key=lambda x: x.NET_NAME))

assert len(NETS_LIST) == len(set([chain.NET_NAME for chain in NETS_LIST])), "NET_NAME must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.datadir_subdir() for chain in NETS_LIST])), "datadir must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.cli_flag() for chain in NETS_LIST])), "cli_flag must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.config_key() for chain in NETS_LIST])), "config_key must be unique for each concrete AbstractNet"

# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinMainnet  # type: Type[AbstractNet]

class BitcoinSimnet:
    NET_NAME = "simnet"
    BOLT11_HRP = "sb"
    SEGWIT_HRP = "sb"
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x7b
    WIF_PREFIX = 0x64
