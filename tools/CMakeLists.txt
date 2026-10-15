# E1 host microbenchmark campaign (plan B-51).
#
# Two roles, deliberately separated:
#   - e1_bench is an EXECUTABLE, because a benchmark running inside the
#     test suite would contend with the rest of the suite for CPU and
#     publish numbers nobody can reproduce.
#   - c_e1_smoke (below) exists ONLY to execute the matrix once so every
#     backend call path is covered. It retains nothing; the real campaign
#     runs on the owner's machine with frequency lock and pinning (B-51.2
#     lab procedure) through tools/e1_run.py.
#
# Source files are listed directly rather than linked as libraries because
# qc_sha256/qc_hmac/qc_hkdf/qc_prof have no library targets in this tree -
# matching how every other test target consumes them.
add_executable(e1_bench e1_bench.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_prof.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_sha256.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hmac.c
    ${CMAKE_SOURCE_DIR}/crypto/qc_hkdf.c)
target_include_directories(e1_bench PRIVATE
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(e1_bench PRIVATE qc_kem qc_dsa qc_aead)

# SMOKE ONLY - not a measurement. Runs the full op x level matrix once each
# with a tiny N so every backend call path actually executes in CI. The
# earlier revision had NO test covering this binary at all, which is how a
# buffer sized for ML-KEM was handed to ML-DSA unnoticed: it compiled, and
# nothing ever ran it. It prints rows; nothing here retains them as a
# dataset (only tools/e1_run.py does that, and only under a green gate).
add_test(NAME c_e1_smoke COMMAND e1_bench ci-smoke 2)
set_tests_properties(c_e1_smoke PROPERTIES TIMEOUT 600)
