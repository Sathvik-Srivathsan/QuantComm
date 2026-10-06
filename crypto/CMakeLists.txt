# crypto/ — host-side crypto library for QuantComm.
#
# Own-code primitives (qc_sha256/qc_hmac/qc_hkdf) stay compiled directly into
# their test targets; qc_aead is a library because it pulls in vendored mbedTLS.
#
# F4: AES-256-GCM delegates to mbedTLS 3.6.4 built against the pruned config
# crypto/mbedtls_config_qc.h. The same config file is used for the ESP-IDF
# target build so host/target configuration cannot drift.

set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR}/third_party/mbedtls)

# Sources required by MBEDTLS_AES_C + MBEDTLS_GCM_C, plus the
# MBEDTLS_BLOCK_CIPHER_C that mbedTLS auto-enables when CIPHER_C is absent
# (config_adjust_legacy_crypto.h). Deliberately NOT the upstream library/*.c
# glob: that would compile modules the pruned config never enables.
# Why each file is here:
#   aes.c             AES block cipher (MBEDTLS_AES_C).
#   block_cipher.c    128-bit-block abstraction GCM is built on.
#   constant_time.c   mbedtls_ct_memcmp for the tag check.
#   gcm.c             GCM mode (MBEDTLS_GCM_C).
#   platform.c        calloc/free (MBEDTLS_PLATFORM_MEMORY).
#   platform_util.c   elision-resistant zeroize.
set(MBEDTLS_SOURCES
    ${MBEDTLS_DIR}/library/aes.c
    ${MBEDTLS_DIR}/library/block_cipher.c
    ${MBEDTLS_DIR}/library/constant_time.c
    ${MBEDTLS_DIR}/library/gcm.c
    ${MBEDTLS_DIR}/library/platform.c
    ${MBEDTLS_DIR}/library/platform_util.c
)

add_library(qc_aead STATIC qc_aead.c ${MBEDTLS_SOURCES})

# include/ is PUBLIC (consumers may include mbedtls headers); library/ is
# PRIVATE (internal headers like block_cipher_internal.h must not leak).
target_include_directories(qc_aead PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MBEDTLS_DIR}/include
)
target_include_directories(qc_aead PRIVATE
    ${MBEDTLS_DIR}/library
)

# build_info.h includes the pruned config by name.
target_compile_definitions(qc_aead PUBLIC
    MBEDTLS_CONFIG_FILE="mbedtls_config_qc.h"
)

# Our adapter is held to the repo-wide -Werror bar. Vendored upstream sources
# are compiled warning-clean-off: they are not our code to fix, and upstream
# targets may not be pedantic-clean. Scoped to these files only.
set_source_files_properties(${MBEDTLS_SOURCES} PROPERTIES COMPILE_OPTIONS "-w")