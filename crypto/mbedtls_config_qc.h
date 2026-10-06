/* mbedtls_config_qc.h — pruned mbedTLS config for QuantComm (F4 decision).
 * AES-256-GCM path ONLY. Everything else (TLS, X.509, RSA, ECDH, ECDSA,
 * DHM, PK, NET, TIMING, DEBUG) stays off. This file's SHA256 is recorded
 * in the build record; host and target builds MUST use this identical
 * file (config drift between reference/host and optimized/target builds
 * invalidates ref-vs-opt comparisons — see techstack F4 risks).
 * Used via -DMBEDTLS_CONFIG_FILE="mbedtls_config_qc.h".
 */
#ifndef QC_MBEDTLS_CONFIG_H
#define QC_MBEDTLS_CONFIG_H

/* Platform + memory (calloc/free). No threading (single-threaded callers). */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY

/* Symmetric core: AES (with HW hooks on ESP-IDF, portable C on host) + GCM.
 *
 * MBEDTLS_CIPHER_C is deliberately NOT defined. mbedTLS config logic
 * (config_adjust_legacy_crypto.h) then auto-enables MBEDTLS_BLOCK_CIPHER_C
 * for GCM, which is the lightweight 128-bit-block abstraction used by
 * gcm.c/block_cipher.c. Defining CIPHER_C instead would force the full
 * multi-cipher wrapper (cipher.c, cipher_wrap.c, md.c, ...) and pull in
 * unused code. BLOCK_CIPHER_C is therefore NOT spelled out here — it is
 * auto-enabled, and crypto/CMakeLists.txt documents the resulting set.
 */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_GCM_C

/* MBEDTLS_VERSION_C deliberately absent: the adapter's only version
 * need is the compile-time MBEDTLS_VERSION_NUMBER floor in qc_aead.c,
 * which comes from build_info.h and needs no version.c. */

/* Everything else intentionally absent (TLS, X.509, PK, RSA, ECP/ECDH/ECDSA,
 * DHM, MD (our HMAC/HKDF are own code), SHAxxx (own code), NET, TIMING,
 * DEBUG, ERROR strings, test hooks, CIPHER_C, CCM/CHACHAPOLY, PSA).
 * AESNI_C/AESCE_C are target-only acceleration; ESP-IDF's mbedTLS build
 * selects those itself. Host build stays portable C. */

#endif
