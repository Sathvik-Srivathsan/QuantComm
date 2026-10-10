add_executable(test_smoke test_smoke.c)
target_link_libraries(test_smoke PRIVATE unity)
add_test(NAME c_smoke COMMAND test_smoke)

# L0/L1 crypto tests link unit sources + test-only RNG directly.
# (crypto/ gains its own lib once adapters outnumber test files.)
add_executable(test_sha256 test_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c)
target_include_directories(test_sha256 PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_sha256 PRIVATE unity)
add_test(NAME c_sha256 COMMAND test_sha256)

add_executable(test_rng test_rng.c
    ${CMAKE_SOURCE_DIR}/crypto/test_rng.c)
target_include_directories(test_rng PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_rng PRIVATE unity)
add_test(NAME c_rng COMMAND test_rng)

add_executable(test_hmac test_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c)
target_include_directories(test_hmac PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_hmac PRIVATE unity)
add_test(NAME c_hmac COMMAND test_hmac)

add_executable(test_hkdf test_hkdf.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_hkdf PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_hkdf PRIVATE unity)
add_test(NAME c_hkdf COMMAND test_hkdf)

add_executable(test_kdf test_kdf.c
    ${CMAKE_SOURCE_DIR}/core/qc_kdf.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_kdf PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_kdf PRIVATE unity)
add_test(NAME c_kdf COMMAND test_kdf)

add_executable(test_ratchet test_ratchet.c
    ${CMAKE_SOURCE_DIR}/core/qc_ratchet.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_ratchet PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_ratchet PRIVATE unity)
add_test(NAME c_ratchet COMMAND test_ratchet)

add_executable(test_codec test_codec.c
    ${CMAKE_SOURCE_DIR}/core/qc_codec.c)
target_include_directories(test_codec PRIVATE
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(test_codec PRIVATE unity)
add_test(NAME c_codec COMMAND test_codec)

# Replay cache unit links SHA-256 (key binds H(ct_S)).
add_executable(test_replay test_replay.c
    ${CMAKE_SOURCE_DIR}/core/qc_replay.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c)
target_include_directories(test_replay PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_replay PRIVATE unity)
add_test(NAME c_replay COMMAND test_replay)

# Epoch/slot/counter/window unit is dependency-free (own CRC32).
add_executable(test_epoch test_epoch.c
    ${CMAKE_SOURCE_DIR}/core/qc_epoch.c)
target_include_directories(test_epoch PRIVATE
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(test_epoch PRIVATE unity)
add_test(NAME c_epoch COMMAND test_epoch)

# Ratchet receiver policy links the ratchet unit + its HKDF deps.
add_executable(test_rsync test_rsync.c
    ${CMAKE_SOURCE_DIR}/core/qc_rsync.c
    ${CMAKE_SOURCE_DIR}/core/qc_ratchet.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_rsync PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_rsync PRIVATE unity)
add_test(NAME c_rsync COMMAND test_rsync)

# Manifest unit links the DSA adapter library (verify under enrolled key).
add_executable(test_manifest test_manifest.c
    ${CMAKE_SOURCE_DIR}/core/qc_manifest.c)
target_include_directories(test_manifest PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_manifest PRIVATE qc_dsa unity)
add_test(NAME c_manifest COMMAND test_manifest)

# Manifest NVS wiring links manifest + persist TU + store + file backend
# + HKDF/HMAC/SHA (image MAC) + DSA lib (level/pk-size validation).
add_executable(test_manifest_nvs test_manifest_nvs.c
    ${CMAKE_SOURCE_DIR}/core/qc_manifest.c
    ${CMAKE_SOURCE_DIR}/core/qc_manifest_persist.c
    ${CMAKE_SOURCE_DIR}/core/qc_store.c
    ${CMAKE_SOURCE_DIR}/core/qc_store_file.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_manifest_nvs PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_manifest_nvs PRIVATE qc_aead qc_dsa unity)
add_test(NAME c_manifest_nvs COMMAND test_manifest_nvs)

# Alarm path links frame lib + DSA lib + manifest (threshold gate).
add_executable(test_alarm test_alarm.c
    ${CMAKE_SOURCE_DIR}/core/qc_alarm.c
    ${CMAKE_SOURCE_DIR}/core/qc_manifest.c)
target_include_directories(test_alarm PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_alarm PRIVATE qc_frame qc_dsa unity)
add_test(NAME c_alarm COMMAND test_alarm)

# DRBG links the deterministic test entropy provider (never prod).
add_executable(test_drbg test_drbg.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_drbg.c
    ${CMAKE_SOURCE_DIR}/crypto/test_entropy.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c)
target_include_directories(test_drbg PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_drbg PRIVATE unity)
add_test(NAME c_drbg COMMAND test_drbg)

# Production RNG path links the REAL entropy TU (live getrandom — the
# only test closure containing it; audit F3). Never the test injector.
add_executable(test_prod_rng test_prod_rng.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_rng_prod.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_drbg.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_entropy.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c)
target_include_directories(test_prod_rng PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_prod_rng PRIVATE unity)
add_test(NAME c_prod_rng COMMAND test_prod_rng)

# Store links HKDF + AEAD lib (wrap + file MAC) + zeroize.
add_executable(test_store test_store.c
    ${CMAKE_SOURCE_DIR}/core/qc_store.c
    ${CMAKE_SOURCE_DIR}/core/qc_store_file.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(test_store PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_store PRIVATE qc_aead unity)
add_test(NAME c_store COMMAND test_store)

# Outage buffer links no crypto (verbatim wire storage + file mirror).
add_executable(test_buf test_buf.c
    ${CMAKE_SOURCE_DIR}/core/qc_buf.c
    ${CMAKE_SOURCE_DIR}/core/qc_buf_file.c)
target_include_directories(test_buf PRIVATE
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(test_buf PRIVATE unity)
add_test(NAME c_buf COMMAND test_buf)

# Merkle unit links SHA-256 (tree hashing).
add_executable(test_merkle test_merkle.c
    ${CMAKE_SOURCE_DIR}/core/qc_merkle.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c)
target_include_directories(test_merkle PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_merkle PRIVATE unity)
add_test(NAME c_merkle COMMAND test_merkle)

# Telemetry frame unit links the AEAD library (payload protection).
add_library(qc_frame STATIC
    ${CMAKE_SOURCE_DIR}/core/qc_frame.c)
target_include_directories(qc_frame PUBLIC
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(qc_frame PUBLIC qc_aead)
add_executable(test_frame test_frame.c)
target_link_libraries(test_frame PRIVATE qc_frame unity)
add_test(NAME c_frame COMMAND test_frame)

# Server pipeline links core units + own-code crypto + KEM + AEAD libs.
# test_rng.c provides the deterministic N_S/coins (never production).
add_executable(test_server test_server.c
    ${CMAKE_SOURCE_DIR}/core/qc_server.c
    ${CMAKE_SOURCE_DIR}/core/qc_replay.c
    ${CMAKE_SOURCE_DIR}/core/qc_codec.c
    ${CMAKE_SOURCE_DIR}/core/qc_kdf.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c
    ${CMAKE_SOURCE_DIR}/crypto/test_rng.c)
target_include_directories(test_server PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_server PRIVATE qc_kem unity)
add_test(NAME c_server COMMAND test_server)

# AEAD adapter links the pruned-mbedTLS library (F4). Include dirs and the
# MBEDTLS_CONFIG_FILE define come transitively from the qc_aead target.
add_executable(test_aead test_aead.c)
target_link_libraries(test_aead PRIVATE qc_aead unity)
add_test(NAME c_aead COMMAND test_aead)

# KEM adapter links the three per-level mlkem-native backends (B-01/B-10).
add_executable(test_kem test_kem.c)
target_link_libraries(test_kem PRIVATE qc_kem unity)
add_test(NAME c_kem COMMAND test_kem)

# DSA adapter links the three per-level mldsa-native backends (B-01/B-11).
add_executable(test_dsa test_dsa.c)
target_link_libraries(test_dsa PRIVATE qc_dsa unity)
add_test(NAME c_dsa COMMAND test_dsa)

# Seeded deterministic negative-matrix fuzz for both PQC adapters
# (B-10.6/B-11.6). Links the test-only RNG (never production).
# Generous timeout: DSA-87 signs dominate; hang = fail.
add_executable(test_fuzz test_fuzz.c
    ${CMAKE_SOURCE_DIR}/crypto/test_rng.c)
target_include_directories(test_fuzz PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(test_fuzz PRIVATE qc_kem qc_dsa unity)
add_test(NAME c_fuzz COMMAND test_fuzz)
set_tests_properties(c_fuzz PROPERTIES TIMEOUT 300)

# Wycheproof independent cross-check (B-10.3/B-11.3, B-02.3 gate).
# Vectors vendored as hex tables (tools/wycheproof_to_c.py); no RNG.
add_executable(test_xcheck test_xcheck.c)
target_link_libraries(test_xcheck PRIVATE qc_kem qc_dsa unity)
add_test(NAME c_xcheck COMMAND test_xcheck)
set_tests_properties(c_xcheck PROPERTIES TIMEOUT 300)
# The generated vectors header holds string literals past the C99 4095-char
# portability minimum (a 2400-byte key is 4800 hex chars; chunking adjacent
# literals does not help — the limit applies after concatenation). GCC and
# MSVC both accept them; silenced for this generated-data TU only (a
# per-literal warning here would be pure noise hiding real warnings).
# Everything else stays under repo-wide -Werror.
set_source_files_properties(test_xcheck.c PROPERTIES
    COMPILE_OPTIONS "-Wno-overlength-strings")
