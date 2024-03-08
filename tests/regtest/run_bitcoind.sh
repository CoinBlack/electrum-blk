#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.blackmore
cat > ~/.blackmore/blackmore.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
fallbackfee=0.0002
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.blackmore/regtest
bitcoind -regtest &
sleep 6
blackmore-cli createwallet test_wallet
addr=$(blackmore-cli getnewaddress)
blackmore-cli generatetoaddress 150 $addr
tail -f ~/.blackmore/regtest/debug.log
