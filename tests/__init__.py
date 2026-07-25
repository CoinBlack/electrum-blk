import asyncio
import os
import unittest
import threading
import tempfile
import shutil
import functools
import inspect
from typing import TYPE_CHECKING, List

import sys
import pkgutil
import builtins

import electrum_blk
import electrum_blk.logging
from electrum_blk import constants
from electrum_blk import util
from electrum_blk.util import OldTaskGroup
from electrum_blk.logging import Logger
from electrum_blk.wallet import restore_wallet_from_text
import electrum_blk.bitcoin


# Inject electrum into builtins so it's globally accessible in tests
setattr(builtins, 'electrum', electrum_blk)

# Walk and import all submodules of electrum_blk to populate sys.modules
sys.modules['electrum'] = electrum_blk
for _, module_name, _ in pkgutil.walk_packages(electrum_blk.__path__, electrum_blk.__name__ + '.'):
    try:
        module = __import__(module_name, fromlist=['*'])
    except Exception:
        continue
    alias = module_name.replace('electrum_blk.', 'electrum.')
    sys.modules[alias] = module

# Also make sure everything in sys.modules starting with electrum_blk is aliased
for name, module in list(sys.modules.items()):
    if name.startswith('electrum_blk.'):
        alias = name.replace('electrum_blk.', 'electrum.')
        if alias not in sys.modules:
            sys.modules[alias] = module


# Override total supply limit to Bitcoin's 21M for testing regex/amount limits
# (production value is 100M BLK, but tests use Bitcoin's 21M cap)
electrum_blk.bitcoin.TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 21000000

import electrum_blk.blockchain
def test_hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return electrum_blk.blockchain.hash_raw_header(electrum_blk.blockchain.serialize_header(header))
electrum_blk.blockchain.hash_header = test_hash_header

# Override network constants to use Bitcoin values during tests, since the entire
# test suite is inherited from upstream and expects Bitcoin addresses, derivations, and WIF formats.
constants.BitcoinMainnet.WIF_PREFIX = 0x80
constants.BitcoinMainnet.ADDRTYPE_P2PKH = 0
constants.BitcoinMainnet.ADDRTYPE_P2SH = 5
constants.BitcoinMainnet.SEGWIT_HRP = "bc"
constants.BitcoinMainnet.BOLT11_HRP = "bc"
constants.BitcoinMainnet.BIP44_COIN_TYPE = 0
constants.BitcoinMainnet.GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

constants.BitcoinTestnet.WIF_PREFIX = 0xef
constants.BitcoinTestnet.ADDRTYPE_P2PKH = 111
constants.BitcoinTestnet.ADDRTYPE_P2SH = 196
constants.BitcoinTestnet.BIP44_COIN_TYPE = 1
constants.BitcoinTestnet.GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"

constants.BitcoinRegtest.WIF_PREFIX = 0xef
constants.BitcoinRegtest.ADDRTYPE_P2PKH = 111
constants.BitcoinRegtest.ADDRTYPE_P2SH = 196
constants.BitcoinRegtest.BIP44_COIN_TYPE = 1
constants.BitcoinRegtest.GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

# Override fee constants to Bitcoin values for test compatibility.
# The test suite is inherited from upstream Electrum and uses hardcoded
# Bitcoin transactions built with Bitcoin-level fee rates.
import electrum_blk.fee_policy as _fee_policy
_fee_policy.FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                                     50000, 70000, 100000, 150000, 200000, 300000]
_fee_policy.FEERATE_MAX_DYNAMIC = 1500000
_fee_policy.FEERATE_WARNING_HIGH_FEE = 600000
_fee_policy.FEERATE_MIN_RELAY = 100
_fee_policy.FEERATE_DEFAULT_RELAY = 1000
_fee_policy.FEERATE_MAX_RELAY = 50000

if TYPE_CHECKING:
    from .test_lnpeer import MockLNWallet


# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


electrum_blk.logging._configure_stderr_logging(verbosity="*")

electrum_blk.util.AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP = True


class ElectrumTestCase(unittest.IsolatedAsyncioTestCase, Logger):
    """Base class for our unit tests."""

    TESTNET = False  # there is also an @as_testnet decorator to run single tests in testnet mode
    REGTEST = False
    TEST_ANCHOR_CHANNELS = True
    WALLET_FILES_DIR = os.path.join(os.path.dirname(__file__), "test_storage_upgrade")
    # maxDiff = None  # for debugging

    # some unit tests are modifying globals... so we run sequentially:
    _test_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        Logger.__init__(self)
        unittest.IsolatedAsyncioTestCase.__init__(self, *args, **kwargs)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        assert not (cls.REGTEST and cls.TESTNET), "regtest and testnet are mutually exclusive"
        if cls.REGTEST:
            constants.BitcoinRegtest.set_as_network()
        elif cls.TESTNET:
            constants.BitcoinTestnet.set_as_network()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        if cls.TESTNET or cls.REGTEST:
            constants.BitcoinMainnet.set_as_network()

    def setUp(self):
        have_lock = self._test_lock.acquire(timeout=0.1)
        if not have_lock:
            # This can happen when trying to run the tests in parallel,
            # or if a prior test raised  during `setUp` or `asyncSetUp` and never released the lock.
            raise Exception("timed out waiting for test_lock")
        super().setUp()
        self.unittest_base_path = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        self.electrum_path = os.path.join(self.unittest_base_path, "electrum")
        util.make_dir(self.electrum_path)
        assert util._asyncio_event_loop is None, "global event loop already set?!"
        self._lnworkers_created = []  # type: List[MockLNWallet]

    async def asyncSetUp(self):
        await super().asyncSetUp()
        loop = util.get_asyncio_loop()
        # IsolatedAsyncioTestCase creates event loops with debug=True, which makes the tests take ~4x time
        if not (os.environ.get("PYTHONASYNCIODEBUG") or os.environ.get("PYTHONDEVMODE")):
            loop.set_debug(False)
        util._asyncio_event_loop = loop

    async def asyncTearDown(self):
        # clean up lnworkers
        async with OldTaskGroup() as group:
            for lnworker in self._lnworkers_created:
                await group.spawn(lnworker.stop())
        self._lnworkers_created.clear()
        await super().asyncTearDown()

    def tearDown(self):
        util.callback_mgr.clear_all_callbacks()
        shutil.rmtree(self.unittest_base_path)
        super().tearDown()
        util._asyncio_event_loop = None  # cleared here, at the ~last possible moment. asyncTearDown is too early.
        self._test_lock.release()

    def create_mock_lnwallet(
        self,
        *,
        name: str,
    ) -> 'MockLNWallet':
        from .lnhelpers import _create_mock_lnwallet
        data_dir = tempfile.mkdtemp(prefix="lnwallet-", dir=self.unittest_base_path)
        lnwallet = _create_mock_lnwallet(name=name, has_anchors=self.TEST_ANCHOR_CHANNELS, data_dir=data_dir)
        self._lnworkers_created.append(lnwallet)
        return lnwallet

    def get_wallet_file_path(self, wallet_name: str) -> str:
        return os.path.join(self.WALLET_FILES_DIR, wallet_name)


def as_testnet(func):
    """Function decorator to run a single unit test in testnet mode.

    NOTE: this is inherently sequential; tests running in parallel would break things
    """
    old_net = constants.net
    if inspect.iscoroutinefunction(func):
        async def run_test(*args, **kwargs):
            try:
                constants.BitcoinTestnet.set_as_network()
                return await func(*args, **kwargs)
            finally:
                constants.net = old_net
    else:
        def run_test(*args, **kwargs):
            try:
                constants.BitcoinTestnet.set_as_network()
                return func(*args, **kwargs)
            finally:
                constants.net = old_net
    return run_test

def as_regtest(func):
    """Function decorator to run a single unit test in regtest mode.

    NOTE: this is inherently sequential; tests running in parallel would break things
    """
    old_net = constants.net
    if inspect.iscoroutinefunction(func):
        async def run_test(*args, **kwargs):
            try:
                constants.BitcoinRegtest.set_as_network()
                return await func(*args, **kwargs)
            finally:
                constants.net = old_net
    else:
        def run_test(*args, **kwargs):
            try:
                constants.BitcoinRegtest.set_as_network()
                return func(*args, **kwargs)
            finally:
                constants.net = old_net
    return run_test


@functools.wraps(restore_wallet_from_text)
def restore_wallet_from_text__for_unittest(*args, gap_limit=2, gap_limit_for_change=1, **kwargs):
    """much lower default gap limits (to save compute time)"""
    return restore_wallet_from_text(
        *args,
        gap_limit=gap_limit,
        gap_limit_for_change=gap_limit_for_change,
        **kwargs,
    )
