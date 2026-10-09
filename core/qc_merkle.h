/* qc_merkle.h — Merkle batch attestation core (plan B-24.3).
 *
 * Leaves bind (reading bytes + frame counter + class):
 *   leaf = SHA-256("QC-ATTEST" || class u8 || counter u64-BE || reading).
 * The QC-ATTEST domain label is B-12.2's registry entry for attestation
 * inputs (exact fit — no new label minted). Tree: binary SHA-256 over
 * concatenated children (plain left||right per B-24.3 — no second prefix
 * is specified; noted, not invented); odd leaf promoted unchanged;
 * single-leaf batch root equals the leaf hash.
 *
 * Memory discipline: no alloc, no static state. Callers supply scratch
 * (n*32 B for n leaves; upper levels fold in place). Proof = sibling
 * hashes leaf-to-root + leaf index (order bits derived from the index).
 *
 * Composition (not code here): device signs the root with ML-DSA once per
 * T_a (qc_dsa_sign); server verifies (qc_dsa_verify) then trusts the
 * batch. Empty intervals sign nothing (caller policy: never call root
 * with n == 0 — it returns BAD_ARG). Drop distinguisher values
 * (last_root, counter range) flow from batch bookkeeping into frame
 * headers (qc_frame fields); retention/ Ta scheduling belong to B-40/B-51.
 */
#ifndef QC_MERKLE_H
#define QC_MERKLE_H

#include <stddef.h>
#include <stdint.h>

#define QC_MERKLE_HASH_LEN 32
#define QC_MERKLE_LABEL_ATTEST "QC-ATTEST"

typedef enum {
    QC_MERKLE_OK = 0,
    QC_MERKLE_BAD_ARG,  /* NULL pointers, n == 0, undersized buffers. */
} qc_merkle_rc;

/* Leaf hash over one framed reading. */
qc_merkle_rc qc_merkle_leaf(uint8_t cls, uint64_t counter,
                            const uint8_t *reading, size_t reading_len,
                            uint8_t leaf[QC_MERKLE_HASH_LEN]);

/* Tree root over n leaf hashes (leaves = n*32 contiguous bytes).
 * scratch must hold >= n*32 bytes (fold-in-place workspace). */
qc_merkle_rc qc_merkle_root(const uint8_t *leaves, size_t n,
                            uint8_t *scratch, size_t scratch_len,
                            uint8_t root[QC_MERKLE_HASH_LEN]);

/* Proof depth upper bound for n leaves (caller sizing). */
size_t qc_merkle_proof_max(size_t n);

/* Inclusion proof for leaf `index`: siblings leaf-to-root into
 * proof[][32] (cap = proof_cap entries); *depth_out = levels used.
 * SMALL_BUF equivalent: BAD_ARG when cap < depth. Levels are rebuilt in
 * the caller scratch (>= n*32, same as root); no function-static state.
 * Promotion levels (odd tail) consume no entry — verify() replays the
 * identical skip rule from (n, index), so prover/verifier agree by
 * construction, never by luck. */
qc_merkle_rc qc_merkle_proof(const uint8_t *leaves, size_t n, size_t index,
                             uint8_t *scratch, size_t scratch_len,
                             uint8_t *proof, size_t proof_cap,
                             size_t *depth_out);

/* Verify: recompute root from (leaf, index, proof) and compare.
 * n (leaf count) is REQUIRED, not redundant: promotion-skip decisions
 * (which levels consumed no entry) are recomputed from (n, index), and
 * the per-level left/right order follows the running position. A proof
 * generated under a different n fails closed (hash mismatch), never
 * falsely accepts. */
qc_merkle_rc qc_merkle_verify(const uint8_t leaf[QC_MERKLE_HASH_LEN],
                              size_t n, size_t index,
                              const uint8_t *proof, size_t depth,
                              const uint8_t root[QC_MERKLE_HASH_LEN]);

#endif