/* mldsa_config_qc.h — QuantComm configuration for mldsa-native (B-01/B-11).
 * Selected via -DMLD_CONFIG_FILE="mldsa_config_qc.h" (per-level targets add
 * -DMLD_CONFIG_PARAMETER_SET=44/65/87). This file's SHA256 is recorded in
 * third_party/mldsa/README.md; host and ESP32 builds MUST use this identical
 * file. Mirrors crypto/mlkem_config_qc.h (same option philosophy).
 *
 * - Portable C backend only (native dirs absent from the pruned vendor).
 * - Internal API only (MLD_CONFIG_NO_RANDOMIZED_API): keypair takes an
 *   explicit seed, sign takes explicit rnd — hedged vs deterministic is a
 *   property of the rnd input, always explicit at the call site.
 * - Multilevel build: one static lib per parameter set, symbols namespaced
 *   qc_mldsa{44,65,87}_* (WITH_SHARED on the 44 lib, NO_SHARED on 65/87 —
 *   per-target flags in crypto/CMakeLists.txt, same split as mlkem).
 * - KeyGen PCT off: deterministic reference (revisit for production, B-60).
 * - Default stack allocation. ESP32 note: default ML-DSA-87 sign stack
 *   (~108KB per MLD_TOTAL_ALLOC_87_SIGN) exceeds task budgets — the target
 *   build must use MLD_CONFIG_REDUCE_RAM (~21KB). Host reference keeps the
 *   default profile; B-60 owns the target profile selection.
 */
#ifndef QC_MLDSA_CONFIG_H
#define QC_MLDSA_CONFIG_H

#define MLD_CONFIG_MULTILEVEL_BUILD
#define MLD_CONFIG_NAMESPACE_PREFIX qc_mldsa
#define MLD_CONFIG_NO_RANDOMIZED_API

/* Deliberately absent: native backends (C everywhere),
 * MLD_CONFIG_KEYGEN_PCT (see above), MLD_CONFIG_CUSTOM_ALLOC_FREE
 * (stack default), MLD_CONFIG_REDUCE_RAM (host default profile;
 * B-60 selects the target profile). */

#endif