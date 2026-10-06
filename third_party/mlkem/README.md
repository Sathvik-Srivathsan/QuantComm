# mlkem-native v2.0.0 vendored 2026-10-06 (B-01 decision, B-10 backend).
# Upstream: https://github.com/pq-code-package/mlkem-native
# Source tarball:
#   https://github.com/pq-code-package/mlkem-native/archive/refs/tags/v2.0.0.tar.gz
# Tarball SHA256:
#   76bf71771f09a25f30463218974ae10752d72bca34bbc470c7f6f8655f51d622
# License: Apache-2.0 OR ISC OR MIT (see upstream LICENSE; vendored tree
# keeps no license file — the grant is recorded here and in B-01).
#
# PRUNED vendor: the single-compilation-unit C backend only
# (mlkem_native.c bundles all C sources; native/ dirs dropped, so no
# architecture backends can be silently enabled). Built per parameter set
# with crypto/mlkem_config_qc.h (SHA256 recorded below).
#
# Portions: C90, CBMC memory/type-safety proven; reference fork of FIPS 203.
# Host and ESP32 builds compile this identical tree (C backend both sides).
#
# SHA256 (lowercase) of vendored files — verify on re-vendor:
#   mlkem_native.c                  e533497ae0c31d5023d00cdb25ae5f8646727eee53323fba4107818231ad8956
#   mlkem_native.h                  3546f0f7318fc08d007097add98a77d48a8c1f670e0d8db2c5222e1acaa88ce1
#   src/cbmc.h                      180bf239c5d7b84fa451727546d4fbc9595008382cfc86d4ae5791e0e5a6b910
#   src/common.h                    833c4d8e52822d5a209fdc72ef655f6eb7801fd712c515805d2c5360e58bdaab
#   src/compress.c                  a13d44b3a96962ae982722fba8b1ff6744f16e7b3b760883edfe762061cb26b5
#   src/compress.h                  746ce7e55d088f75220ca0a5b08fc515c033167cbcacfd74be127e14f1f5e128
#   src/context.h                   e6788b29f4883f57752fd8327a80dfc978eb21ad72a0055cbbaaa7b433637edf
#   src/debug.c                     263ac19f2b2bf5c784cbf04fd4c968762abedc6961d44f507c8953b52a38827e
#   src/debug.h                     d1fab329b439fc6dd9c4234f3fe053e74b000d416e0f4e4464542813667f3750
#   src/fips202/fips202.c           fb0654c0b33c45c929fdb2af2287807a7b8f312ac7f3baa3ddfaef0c030ef0b2
#   src/fips202/fips202.h           a5efcf58893aa589dfe25a1069e11ab58408b2ad14e389014a785205300468a1
#   src/fips202/fips202x4.c         2e481ccbafc00765b210725c8e454f2b4dc622844eccf6a0c1e025657fcb5fe8
#   src/fips202/fips202x4.h         c8d2e50f7ccce19822030786a1a99f0892db63ebe5b020fa91a5383c9700dd22
#   src/fips202/keccakf1600.c       461c278b0abb9fde098ee6b34a47056445573cb7aa5c4362d59e35041d0997e5
#   src/fips202/keccakf1600.h       88c06d4c546f46920a65001bcfad8cabb6173fb01ae071e02412c46043bdf54f
#   src/indcpa.c                    526505cbf09ab80e9644563eb808373c502aad2270a0b53c8370510ea4c0b70d
#   src/indcpa.h                    ac6f47c959fdc97aa1882bca5f78ecfcee595ff21769f937866f2c1d1bf29109
#   src/kem.c                       3922156826521429eb250ccb3d54d7beacce14adce26bb3be6d1ef7864342dd3
#   src/kem.h                       ba22bd6de66141138329aaf53aedc73350c4ceaa241a341d0e5136c5df493dbd
#   src/params.h                    450fe3e0e50496921920473ae4321660f178c23d51f1453f3c537ee63c4158cb
#   src/poly.c                      f0e0643a2c3743181b7927a9d47af0930ce7870a9d79671f64e6089fe028982e
#   src/poly.h                      86224c6d1e7ec5a4c0dcd829ae90c0cb43b4855d84dd719973d47e71b8e962d4
#   src/poly_k.c                    56130249963b5b62e97dc6413adeed21f4e542da6531e34cf640baca161fa5ff
#   src/poly_k.h                    839852fd9c8d155f37a7a07dc1116c2ea18fade754b1d882f73c4affef5e62d3
#   src/randombytes.h               137eb6e5854b8e58c2caec6eea86530c8e7495706f6f5b3e007e25a9875e164f
#   src/sampling.c                  9263037c401d0cc4130a6f0dba76299d170b498c330f5d5c32b5ae5921bacd5f
#   src/sampling.h                  d25df90afc96a02a794dcb737236b2cb42cbd2db411ccaf274cf5ea3bf5e3c87
#   src/symmetric.h                 168d0ec3bf50bd45cb0a103d7984e9ccf52f78697718b7e85efdf1beda7abc95
#   src/sys.h                       0ead27bb8c8879b62b29b9bb86c36aeaac270598d42ee2f2258a478eed8efa5c
#   src/verify.c                    f8f89f1b8c8e5811ce134c0d90fb7828027336afeed231dc3ccb7ee6b73b9335
#   src/verify.h                    76fd0af32577f9118d1ea90a66ff77e18cdf99d08dcf1c9df137833041e8492f
#   src/zetas.inc                   303d1abccc4757d49a5c8df5f88080fefef617b7360056db5311bd94354096d4
#
# crypto/mlkem_config_qc.h SHA256:
#   4170bbeb31a29bc31d33be64b065c271830852266819ee6f38178b518c956fce
#
# Re-vendor: bash tools/vendor_pq.sh mlkem <version> (pinned hash required).
# Policy: LTS/stable releases only, hashes updated here.