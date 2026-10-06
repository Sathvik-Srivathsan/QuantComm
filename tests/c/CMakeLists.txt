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
