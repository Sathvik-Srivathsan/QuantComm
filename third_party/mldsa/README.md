# mldsa-native v2.0.0 vendored 2026-10-06 (B-01 decision, B-11 backend).
# Upstream: https://github.com/pq-code-package/mldsa-native
# Source tarball:
#   https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v2.0.0.tar.gz
# Tarball SHA256:
#   97a7305c32b62cbcae97891823176e18ca96d9eaafc3728587d75bb113862a40
# License: Apache-2.0 OR ISC OR MIT (see upstream LICENSE; vendored tree
# keeps no license file — the grant is recorded here and in B-01).
#
# PRUNED vendor: the single-compilation-unit C backend only
# (mldsa_native.c bundles all C sources; native/ dirs dropped). B-11 will
# build per parameter set (44/65/87) with crypto/mldsa_config_qc.h
# (to be written at B-11 time; REDUCE_RAM profile expected for ESP32 —
# default ML-DSA-87 sign stack (~108KB) exceeds task budgets, reduced
# profile is ~21KB).
#
# Portions: C90, CBMC memory/type-safety proven; reference fork of FIPS 204.
# sign() takes explicit caller randomness: hedged (fresh coins) and
# deterministic (fixed coins) variants share one API.
#
# SHA256 (lowercase) of vendored files — verify on re-vendor:
#   mldsa_native.c                  0d7e19d651e629430b1923f3cba2fb2579639d8bd1f156a2dcd2696aa83f846f
#   mldsa_native.h                  b30c04756599aaa15301a13bc6025955f275c1e573fc92f96778a7c972fc4d4d
#   src/cbmc.h                      355704060689792c1ef7307844b486ac54bd397db5474a912cdf1d5ee4e0d2e7
#   src/common.h                    340e0a7c22f807ba020362d3cca7babadec0214c59329ea88c1f6e307686af84
#   src/context.h                   c75d2d0f6555230e5fa6ea9147d523d5375fba247b314fe080d0454f89267719
#   src/ct.c                        5d5641f89ee92f8d33f4489b7746ca20d4226cf6ec9895bf644d4bc8871e5
#   src/ct.h                        706be081c657b742247b25588b6eb75f399f73b84b33ef20179ceeb721731078
#   src/debug.c                     0200f23feaebfd12d35b39232c2ae566f7322d86993f981a705ddc6355a42edc
#   src/debug.h                     4effd0eef9b63bdf434369b69ec5d14293ad7d22031b4f5ba237c69ce2fda383
#   src/fips202/fips202.c           b8984253addafa72a0a127abbc80007509a36f23e63472d3ca54bed1d6e08d85
#   src/fips202/fips202.h           cdae2eb8a2d8970d8cb715e1c34230ee65ed35c75311525eca5232435d93c4e2
#   src/fips202/fips202x4.c         9c3f07deeee40277df068a7a6e28b57df7ea7fc9efefc400c6279f3781620f82
#   src/fips202/fips202x4.h         dc0a3bb0664ea664147df7f4ada4354114627f0fdbbe72981216c59387071a13
#   src/fips202/keccakf1600.c       52b5134e53054d0e4dda93a48471d2d72cffc4b048f918450ac63b613e736328
#   src/fips202/keccakf1600.h       0b8b54a10be173d712d29ac806acb73924b38b4d06c68d35b1dde06a08ed005c
#   src/packing.c                   bc410982aca199135550eebdae4da4533d9c76e1a8ea0b8e0b02df9dccdd7632
#   src/packing.h                   d095e2960591186bb7ae843381dbce5e407d41b62ce8f49b92b24986ce494f90348ccf1
#   src/params.h                    fd15d4b12747bffc17a78dd7e361fff7973e4455e3d3a162e83237f2d3029941
#   src/poly.c                      3bfb1b8f3c2e9fe1f00ca37d0fc64c57f70d0c3f845504989f39e9014799bdc3
#   src/poly.h                      f753c1efdf41252198b268a7e1f04252ed5707aa325e50c17f2846a2c12f18e
#   src/poly_kl.c                   2073e8e6230957f39feabc5d204f8055ae25e60dedb161eff3f3e4894832abe5
#   src/poly_kl.h                   c2a52797f36d676c4f2c889986cddae06cbbd1004e23e09064353137e4cf2a44
#   src/polyvec.c                   bdca075b7f0d7741c649d59350e6eb94884b7160e0baefc5e50be492c1b2070a
#   src/polyvec.h                   707341d7ea21f599dacad64845a7afbf4f78ce8f49b2b24986c7e5cc95813e4d
#   src/polyvec_lazy.c              5bc5b115b16393ca79f44540f5561da544496bda5b5514e1552015a3b83f0a73
#   src/polyvec_lazy.h              08d8f9fda9bc3f27cbbae40ff861f623576c0a2b520b991d666db0d20c3dce52
#   src/randombytes.h               b8ccb9a34818d8e1cd0cfea9b24829ab9949cb88c20ed0648459c5c7d36aa492
#   src/reduce.h                    c726a493163756a9746c71c247e8d8dfdfc96ce5ba85be4bcc0acdebf689e010
#   src/rounding.h                  2fc8dd6f1ce513104287255e35a6087b2d17d2d8a9327eb1791e874c86f5a206
#   src/sign.c                      b4fddbdd7c0e6acb50683dc96319ef9a77c34d7fc6ea24c7ec40bf1a567afe66
#   src/sign.h                      5392dd11d538563c8e89ae449e02fd78eb7c909393bc0596477e21e36e1b7abd
#   src/symmetric.h                 4ed2df211b960a747e29aec04055100470def1ae8c481feb203c27fbc61a0b70
#   src/sys.h                       a3bbf630c21751783547d21126af6e8162e6e0687d96e2d0f1aa14fd2c60d38f
#   src/zetas.inc                   f27b371b78b05875d22e9b98f541f265c5f9358c3ece72dc91137114556d45ee
#
# Re-vendor: bash tools/vendor_pq.sh mldsa <version> (pinned hash required).
# Policy: LTS/stable releases only, hashes updated here.