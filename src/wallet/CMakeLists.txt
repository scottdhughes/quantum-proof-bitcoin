# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.
add_library(bitcoin_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  migrate.cpp
  pq_scriptpubkeyman.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  scriptpubkeyman.cpp
  spend.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
)
set(bitcoin_sqlite_target "")
if(TARGET unofficial::sqlite3::sqlite3)
  set(bitcoin_sqlite_target unofficial::sqlite3::sqlite3)
elseif(TARGET SQLite3::SQLite3)
  set(bitcoin_sqlite_target SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
  set(bitcoin_sqlite_target SQLite::SQLite3)
endif()
target_link_libraries(bitcoin_wallet
  PRIVATE
    core_interface
    bitcoin_common
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)
if(bitcoin_sqlite_target)
  target_link_libraries(bitcoin_wallet PRIVATE ${bitcoin_sqlite_target})
endif()
