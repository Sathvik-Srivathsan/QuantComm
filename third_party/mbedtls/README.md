# mbedTLS 3.6.4 vendored 2026-10-06 (host-side C backend for AES-GCM, F4).
# Source tarball:
#   https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.4.tar.gz
#
# PRUNED vendor: only what the QuantComm build compiles or includes.
# library/ holds the 6 compiled sources plus the 6 internal headers they
# (transitively) include. include/ is kept whole (public headers, small).
# Everything else from upstream (tests/, programs/, scripts/, docs/, ...)
# is deliberately absent — see tools/vendor_mbedtls.sh for the keep-list
# used to re-vendor.
#
# Built with crypto/mbedtls_config_qc.h (pruned: AES-256-GCM path only;
# no TLS/X.509/RSA/ECDH/ECDSA/PSA/CIPHER_C/VERSION_C). The config file's own
# SHA256 is 1c58887c2a79af504842d671c47c7d26ba3187d432b0b5be501ff680a5fbc326
# and must match on the ESP-IDF target build, otherwise the host-vs-target
# configuration hash comparison is invalid.
#
# SHA256 (lowercase) of vendored files — verify on re-vendor:
#   library/aes.c                      f30e6b7139527b41c32f68cc5430ceafa213e7fdf7a39bf4981f6a20cd0e77a1
#   library/block_cipher.c              90d8a053a836d747d5ead61890e711f7150987017912fafc00c4ba08d6a80796
#   library/constant_time.c             64fcbb48a6486f5c069bdbd29359749719169bd97028cf6fe3d3ab39045746a3
#   library/gcm.c                       202ac639d0c3ce4d34025c68614023c1ac9381e80f0b210acf3204ff4a97f8b3
#   library/platform.c                  69f5e0c95478d792ac5654af56817c8272a68c322010e342afacc90e6d57524d
#   library/platform_util.c             5e195c161ebf03afc4640fb0c8f8aa1a962390fc447a02cd91f7545b5d224a4b
#   library/common.h                    60cd8ae44ed2537b178643f0426af9252f47e7211ca579498914324792613203
#   library/alignment.h                 d18086bed998b4cf2a4b99e423f39b274287324f206d8aeb9da31e15947128bd
#   library/block_cipher_internal.h     cfaf450de93abf79ae6efc3b66f2c97e4389730f48b50abd323929a0e4ce30aa
#   library/constant_time_internal.h    cb5acff773c6129b5dcc29052dc927d9aa474a2e6b7f7e27e5fac0e7d7023463
#   library/constant_time_impl.h        5afbdaa93eaa2c750c4f3f2d0338409d8e15845823f870a39744d1cc197b4e60
#   library/ctr.h                       63331eb36d8ea69b4b4dcd2ec059582bcabf51a8ea891db26d37ab033967789f
#
# MBEDTLS_BLOCK_CIPHER_C is auto-enabled by mbedTLS when CIPHER_C is absent;
# crypto/CMakeLists.txt lists exactly the compiled sources rather than
# globbing library/*.c.
#
# Re-vendor policy: LTS versions only, hashes updated here.