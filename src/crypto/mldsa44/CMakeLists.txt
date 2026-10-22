# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.

# Keep this C-only policy after inherited warning groups (Clang14 ordering),
# while honoring explicit caller flags last. Directory scope leaves secp's own
# APPEND_* handling and every default-OFF build unchanged.
string(APPEND CMAKE_C_COMPILE_OBJECT " -Wno-unused-function ${APPEND_CPPFLAGS} ${APPEND_CFLAGS}")

# These objects add no ML-DSA key owner, signer or OS entropy implementation.
# bitcoin_crypto remains the inherited public hash dependency, not a claim that
# the entire node's transitive closure is wallet/RNG-free.
add_library(bitcoin_mldsa44_verify STATIC EXCLUDE_FROM_ALL verify.c contract.cpp)
set_target_properties(bitcoin_mldsa44_verify PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(bitcoin_mldsa44_verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(bitcoin_mldsa44_verify PRIVATE -Werror)
target_link_libraries(bitcoin_mldsa44_verify PRIVATE core_interface bitcoin_crypto)

# No new ML-DSA private dependency; inherited bitcoin_common retains legacy
# wallet/external-signer/RNG support. This is not a whole-node isolation claim.
add_library(bitcoin_mldsa44_node STATIC EXCLUDE_FROM_ALL node.cpp)
target_compile_options(bitcoin_mldsa44_node PRIVATE -Werror)
target_link_libraries(bitcoin_mldsa44_node PUBLIC bitcoin_mldsa44_verify PRIVATE core_interface bitcoin_common)
