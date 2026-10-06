/* mlkem_config_qc.h — QuantComm configuration for mlkem-native (B-01/B-10).
 * Selected via -DMLK_CONFIG_FILE="mlkem_config_qc.h" (per-level targets add
 * -DMLK_CONFIG_PARAMETER_SET=512/768/1024). This file's SHA256 is recorded
 * in third_party/mlkem/README.md; host and ESP32 builds MUST use this
 * identical file.
 *
 * Design decisions (see B-01 record):
 * - Portable C backend only. No native backends (directories absent from
 *   the pruned vendor). Same code runs on host and ESP32/Xtensa.
 * - Derandomized API only (MLK_CONFIG_NO_RANDOMIZED_API). All randomness
 *   enters as caller-supplied coins: tests inject the deterministic RNG,
 *   production passes B-13 provider output. No second RNG inside the KEM.
 * - Multilevel build: one static lib per parameter set, symbols namespaced
 *   qc_mlkem{512,768,1024}_* (MLK_CONFIG_MULTILEVEL_BUILD).
 * - KeyGen PCT off: the pairwise-consistency test needs internal RNG and
 *   breaks reference determinism. Revisit for production at B-60.
 * - Default stack allocation (no custom alloc). Published budgets
 *   (MLK_TOTAL_ALLOC_* in mlkem_native.h) are asserted by B-10 stack tests.
 */
#ifndef QC_MLKEM_CONFIG_H
#define QC_MLKEM_CONFIG_H

#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_NAMESPACE_PREFIX qc_mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
/* NOTE: the level infix on definitions additionally requires
 * MLK_CONFIG_MULTILEVEL_WITH_SHARED (exactly one TU: the 512 lib,
 * which also provides the shared code) or MLK_CONFIG_MULTILEVEL_NO_SHARED
 * (768/1024 libs). Those come from crypto/CMakeLists.txt per target, not
 * from this file — and consumers must link all three libs. */

/* Deliberately absent: MLK_CONFIG_USE_NATIVE_BACKEND_ARITH/FIPS202
 * (C backend everywhere), MLK_CONFIG_KEYGEN_PCT (see above),
 * MLK_CONFIG_CUSTOM_ALLOC_FREE (stack default),
 * MLK_CONFIG_CUSTOM_RANDOMBYTES (no randomized API remains). */

#endif