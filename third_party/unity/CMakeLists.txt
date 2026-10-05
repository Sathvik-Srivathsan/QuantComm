# Unity v2.6.0 vendored 2026-10-05.
# Source: https://github.com/ThrowTheSwitch/Unity/archive/refs/tags/v2.6.0.tar.gz
# SHA256 (verify on re-vendor):
#   unity.c            ee69607f977cf2653762cb3a84da8a122a0a5bbe6c3308ca1f59e443b1890cf5
#   unity.h            e20bed56a8172986ff9f65933351b8b9df62996b77045ed8787d631223fe6eb3
#   unity_internals.h  c4220e36bc7c66f81a0f0b026e694865f3f33e6c8b48113dedd8db1d50ce0716
# Re-vendor policy: version bumps only (never master); record hashes here.
add_library(unity STATIC unity.c)
target_include_directories(unity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
