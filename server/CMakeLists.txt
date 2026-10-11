# server/ — B-40 service host + crypto servant (LOCAL build).
# srv_crypto links the audited adapters statically (no shared libs).
add_executable(srv_crypto
    srv_crypto.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_drbg.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_entropy.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_rng_prod.c)
target_include_directories(srv_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto)
target_link_libraries(srv_crypto PRIVATE qc_kem qc_dsa qc_aead)
