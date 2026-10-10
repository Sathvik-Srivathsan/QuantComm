/* qc_manifest_persist.h — manifest NVS wiring (plan B-25, B-13 backend).
 *
 * The manifest store is RAM; this TU persists it across reboot:
 *   image file = magic "QCM1" || version u32 || body_len u32 || body ||
 *     level u32 || pk_len u16 || pk || HMAC-32, BE, exact sizes.
 *   HMAC key = HKDF-Expand(storage root, "QC-STORE-MFT", 32).
 * The qc_store manifest_version slot is the ANTI-ROLLBACK ANCHOR
 * (persisted-max wins): every persist bumps it; every restore refuses
 * an image older than it (STALE, RAM untouched).
 *
 * Crash order (write-then-use): image file first (temp+rename), store
 * file second. A crash between leaves image NEWER than slot — restore
 * adopts max, so the torn pair still converges forward (never back).
 * Impossible torn direction (store newer than image) means external
 * deletion/tamper -> MALFORMED, never silent SL1.
 *
 * Restore matrix (fresh ms + fresh ns, root supplied at boot — the root
 * itself is never in either file):
 *   neither file      -> NOT_FOUND (fresh device: SL1 static floors +
 *                        re-enrollment own this path, B-41; this TU
 *                        invents no floors and no keys).
 *   store only        -> MALFORMED (slot proves prior provisioning;
 *                        missing image is tamper, not loss).
 *   image only        -> MALFORMED (anchor gone: cannot anti-rollback).
 *   both, MAC bad     -> MALFORMED. Bad structure/level/pk_len -> same.
 *   image older slot  -> STALE (ms/ns-RAM untouched).
 *   else              -> adopt (slot RAM synced upward when image newer;
 *                        next persist writes it; rate window zeroed —
 *                        RAM-only by design, reboot resets the 6/h cap,
 *                        negligible: physical reboot for 6 extra verifies).
 * Persist requires an applied manifest (initialized + has_manifest +
 * version != 0), else BAD_ARG. Persist-then-act is CALLER order
 * (write-then-use: floors must be durable before first transmission
 * under them — same rule as epoch; this unit cannot enforce it).
 *
 * Store rc mapping: BAD_ARG passes through; store STALE on the slot
 * bump passes through as STALE (caller persisted out of order — a bug);
 * other store failures -> MALFORMED (channel fault; torn pair still
 * converges via max-wins — documented, not silent).
 */
#ifndef QC_MANIFEST_PERSIST_H
#define QC_MANIFEST_PERSIST_H

#include <stddef.h>
#include <stdint.h>

#include "qc_manifest.h"
#include "qc_store.h"

/* ns must be opened (has_root) — persist never opens it (the store may
 * hold caller state such as Kdev that open would clear). */
qc_mft_rc qc_manifest_persist(const qc_manifest_store *ms, qc_store *ns,
                              const char *store_path, const char *img_path,
                              const uint8_t *store_nonce);

qc_mft_rc qc_manifest_restore(qc_manifest_store *ms, qc_store *ns,
                              const uint8_t root[32],
                              const char *store_path,
                              const char *img_path);

#endif
