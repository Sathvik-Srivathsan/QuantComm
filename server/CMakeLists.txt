# server/ — B-40 service host + crypto servant (LOCAL build).
# srv_crypto links the audited adapters statically (no shared libs).
# Controller verbs (srv_ctl.c) link the frozen controller TUs
# (state/floor/risk/energy/opt/gov — called, never modified).
add_executable(srv_crypto
    srv_crypto.c
    srv_ctl.c
    srv_sim.c
    ${CMAKE_SOURCE_DIR}/core/qc_state.c
    ${CMAKE_SOURCE_DIR}/core/qc_batch.c
    ${CMAKE_SOURCE_DIR}/core/qc_merkle.c
    ${CMAKE_SOURCE_DIR}/core/qc_manifest.c
    ${CMAKE_SOURCE_DIR}/core/qc_floor.c
    ${CMAKE_SOURCE_DIR}/core/qc_risk.c
    ${CMAKE_SOURCE_DIR}/core/qc_energy.c
    ${CMAKE_SOURCE_DIR}/core/qc_opt.c
    ${CMAKE_SOURCE_DIR}/core/qc_gov.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_drbg.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_entropy.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_rng_prod.c)
target_include_directories(srv_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(srv_crypto PRIVATE qc_kem qc_dsa qc_aead)
