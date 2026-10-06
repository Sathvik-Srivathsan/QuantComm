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

# --- mlkem-native (B-01/B-10): one single-compilation-unit lib per level.
# Symbols are namespaced qc_mlkem{512,768,1024}_* via our config +
# MLK_CONFIG_PARAMETER_SET per target. Derandomized API only (no
# randombytes symbol needed); all coins come from the caller.
set(MLKEM_DIR ${CMAKE_SOURCE_DIR}/third_party/mlkem/mlkem)

# Multilevel split (upstream design): exactly one TU compiles the
# level-independent shared code (WITH_SHARED), the others compile only
# their level's code (NO_SHARED) and resolve shared symbols at link time
# from the first lib. Consumers must therefore link all three libs.
function(add_mlkem_level LEVEL SHARED_FLAG)
    set(TGT qc_mlkem${LEVEL})
    add_library(${TGT} STATIC ${MLKEM_DIR}/mlkem_native.c)
    # PRIVATE: PARAMETER_SET differs per lib and must never leak to
    # consumers (qc_kem.c sets it per triple-include block itself;
    # a leaked -D would collide with those in-source #defines).
    target_include_directories(${TGT} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${MLKEM_DIR}
    )
    target_compile_definitions(${TGT} PRIVATE
        MLK_CONFIG_FILE="mlkem_config_qc.h"
        MLK_CONFIG_PARAMETER_SET=${LEVEL}
        ${SHARED_FLAG}
    )
    set_source_files_properties(${MLKEM_DIR}/mlkem_native.c PROPERTIES
        COMPILE_OPTIONS "-w")
endfunction()

add_mlkem_level(512 MLK_CONFIG_MULTILEVEL_WITH_SHARED)
add_mlkem_level(768 MLK_CONFIG_MULTILEVEL_NO_SHARED)
add_mlkem_level(1024 MLK_CONFIG_MULTILEVEL_NO_SHARED)

# qc_kem adapter: triple-includes mlkem_native.h (one level per block),
# so it needs the backend headers + our config, but must NOT see any
# PARAMETER_SET -D (see above). mlkem include dir stays PRIVATE: the
# public qc_kem.h exposes no backend types.
add_library(qc_kem STATIC qc_kem.c)
target_include_directories(qc_kem PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(qc_kem PRIVATE
    ${MLKEM_DIR}
)
target_compile_definitions(qc_kem PRIVATE
    MLK_CONFIG_FILE="mlkem_config_qc.h"
)
target_link_libraries(qc_kem PUBLIC qc_mlkem512 qc_mlkem768 qc_mlkem1024)