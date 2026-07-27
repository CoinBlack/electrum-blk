import shutil
import tempfile
import os
import json
import unittest
from typing import Optional
import asyncio
import inspect

import electrum_blk
from electrum_blk.wallet_db import WalletDBUpgrader, WalletDB, WalletRequiresUpgrade, WalletRequiresSplit
from electrum_blk.wallet import Wallet
from electrum_blk import constants
from electrum_blk import util
from electrum_blk.plugin import Plugins
from electrum_blk.simple_config import SimpleConfig

from . import as_testnet, as_regtest
from .test_wallet import WalletTestCase




# TODO add other wallet types: 2fa, xpub-only
# TODO hw wallet with client version 2.6.x (single-, and multiacc)
class TestStorageUpgrade(WalletTestCase):

    def _get_wallet_str(self):
        test_method_name = inspect.stack()[1][3]
        assert isinstance(test_method_name, str)
        assert test_method_name.startswith("test_upgrade_from_")
        fname = test_method_name[len("test_upgrade_from_"):]
        test_vector_file = self.get_wallet_file_path(fname)
        with open(test_vector_file, "r") as f:
            wallet_str = f.read()
        return wallet_str


##########

    async def test_upgrade_from_client_1_9_8_seeded(self):
        """note: this wallet file is not valid json: it tests the ast.literal_eval()
        fallback in wallet_db.load_data()
        """
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    # TODO pre-2.0 mixed wallets are not split currently
    #async def test_upgrade_from_client_1_9_8_mixed(self):
    #    wallet_str = "{'addr_history':{'B8wByarWnSK9XQigwyay8yWhPAq9huvyBq':[],'BAZmrFupNHVSiyPFkJsdhUhKCaNteiFyyL':[],'BHBy5v4chTa4V6vYmbebEHC2XU9hhJqwQm':[],'BSiKJHqTm2tkDjvthcbn2whBPABnbikJR9':[],'BScmS7Qz5ZcCFt6gaFmdkLW4aSiJ7Z7KvH':[],'BH8wZ5UVwj91MDqcXwK6kXT9dCPvh2DLab':[],'BLVr1EjTjfiP3mBa74vaLsMbmoqAmtuF9z':[],'BMFh1MMVWv4D6hJoBpb6LvadfPenCx4Mx5':[]},'accounts_expanded':{},'master_public_key':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb','use_encryption':False,'seed':'2605aafe50a45bdf2eb155302437e678','accounts':{0:{0:['BHBy5v4chTa4V6vYmbebEHC2XU9hhJqwQm','BScmS7Qz5ZcCFt6gaFmdkLW4aSiJ7Z7KvH','BAZmrFupNHVSiyPFkJsdhUhKCaNteiFyyL','BSiKJHqTm2tkDjvthcbn2whBPABnbikJR9','B8wByarWnSK9XQigwyay8yWhPAq9huvyBq'],1:['BLVr1EjTjfiP3mBa74vaLsMbmoqAmtuF9z','BMFh1MMVWv4D6hJoBpb6LvadfPenCx4Mx5','BH8wZ5UVwj91MDqcXwK6kXT9dCPvh2DLab'],'mpk':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb'}},'imported_keys':{'B8f3qPnsQpTD8FLsEU8mNQsMX6eqsPoGUk':'5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq','BJQjVjdu3NqrmJRsQ9xqJVZ4GwiWd9tzdb':'L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U','B6Y8vaUh1bg6PG7vCJH8hPhJ8CTEFRiemU':'L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM'},'seed_version':4}"
    #    await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_0_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_0_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_1_1_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_2_0_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_3_2_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_4_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_5_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    # seed_version 13 is ambiguous
    # client 2.7.18 created wallets with an earlier "v13" structure
    # client 2.8.3 created wallets with a later "v13" structure
    # client 2.8.3 did not do a proper clean-slate upgrade
    # the wallet here was created in 2.7.18 with a couple privkeys imported
    # then opened in 2.8.3, after which a few other new privkeys were imported
    # it's in some sense in an "inconsistent" state
    async def test_upgrade_from_client_2_8_3_importedkeys_flawed_previous_upgrade_from_2_7_18(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_2_9_3_old_seeded_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_3_2_3_ledger_standard_keystore_changes(self):
        # see #6066
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        wallet = Wallet(db, config=self.config)
        ks = wallet.keystore
        # to simulate ks.opportunistically_fill_in_missing_info_from_device():
        ks._root_fingerprint = "deadbeef"
        ks.is_requesting_to_be_rewritten_to_wallet_file = True
        await wallet.stop()

    async def test_upgrade_from_client_2_9_3_importedkeys_keystore_changes(self):
        # see #6401
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        wallet = Wallet(db, config=self.config)
        wallet.import_private_keys(
            ["p2wpkh:L1cgMEnShp73r9iCukoPE3MogLeueNYRD9JVsfT1zVHyPBR3KqBY"],
            password=None
        )
        await wallet.stop()

    @as_testnet
    async def test_upgrade_from_client_3_3_8_xpub_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_4_0_1_with_invoices(self):
        # wallet with one invoice and one request. seed_version is 31
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    # blackcoin: Lightning Network (LN) features and lntb BOLT11 invoices are omitted in electrum-blk
    # @as_testnet
    # async def _disabled_test_upgrade_from_client_4_5_2_9dk_with_ln(self):
        # This is a realistic testnet wallet, from the "9dk" seed, including some lightning sends/receives,
        # some labels, frozen addresses, saved local txs, invoices/requests, etc. The file also has partial writes.
        # Also, regression test for #8913
        # wallet_str = self._get_wallet_str()
        # await self._upgrade_storage(wallet_str)

    # blackcoin: Lightning Network (LN) features and lntb BOLT11 invoices are omitted in electrum-blk
    # @as_regtest
    # async def _disabled_test_upgrade_from_client_4_6_0_with_unfulfilled_htlcs(self):
        # tests unfulfilled_htlcs conversion in 62->63. seed_version is 60.
        # wallet_str = self._get_wallet_str()
        # await self._upgrade_storage(wallet_str)

##########

    plugins: 'electrum.plugin.Plugins'

    def setUp(self):
        super().setUp()
        gui_name = 'cmdline'
        # TODO it's probably wasteful to load all plugins... only need Trezor
        self.plugins = Plugins(self.config, gui_name)

    def tearDown(self):
        self.plugins.stop()
        self.plugins.stopped_event.wait()
        super().tearDown()

    async def _upgrade_storage(self, wallet_json, accounts=1) -> Optional[WalletDB]:
        if accounts == 1:
            # test manual upgrades
            try:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=False)
            except WalletRequiresUpgrade:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=True)
                await self._sanity_check_upgraded_db(db)
            return db
        else:
            try:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=False)
            except WalletRequiresSplit as e:
                split_data = e._split_data
                self.assertEqual(accounts, len(split_data))
                for item in split_data:
                    data = json.dumps(item)
                    new_db = WalletDB(data, storage=None, upgrade=True)
                    await self._sanity_check_upgraded_db(new_db)

    async def _sanity_check_upgraded_db(self, db):
        wallet = Wallet(db, config=self.config)
        await wallet.stop()

    @staticmethod
    def _load_db_from_json_string(*, wallet_json, upgrade):
        db = WalletDB(wallet_json, storage=None, upgrade=upgrade)
        return db
