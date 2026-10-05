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
