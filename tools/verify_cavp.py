#!/usr/bin/env python3
"""verify_cavp.py — confirm the AES-256-GCM CAVP vectors baked into
tests/c/test_aead.c against an independent implementation.

The vectors come from the NIST CAVP file gcmEncryptExtIV256.rsp
(AES-256, IVlen=96, Taglen=128), transcribed via
quiche/quic/core/crypto/aes_256_gcm_encrypter_test.cc. This script
re-derives every one of them with Python `cryptography` and checks the
ciphertext AND tag byte-for-byte.

Run:  python tools/verify_cavp.py
Exit 0 + "all N/N ..." on success; AssertionError otherwise.

Last verified: 2026-10-06, cryptography 44.x — 9/9 reproduce.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# (key, iv, pt, aad, ct, tag) — hex. Must match test_cavp_* in test_aead.c.
VECTORS = [
    # {256, 96, 0, 0, 128}
    ("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
     "516c33929df5a3284ff463d7", "", "", "",
     "bdc1ac884d332457a1d2664f168c76f0"),
    ("5fe0861cdc2690ce69b3658c7f26f8458eec1c9243c5ba0845305d897e96ca0f",
     "770ac1a5a3d476d5d96944a1", "", "", "",
     "196d691e1047093ca4b3d2ef4baba216"),
    # {256, 96, 0, 128, 128}
    ("78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
     "d79cf22d504cc793c3fb6c8a", "", "b96baa8c1c75a671bfb2d08d06be5f36", "",
     "3e5d486aa2e30b22e040b85723a06e76"),
    ("4457ff33683cca6ca493878bdc00373893a9763412eef8cddb54f91318e0da88",
     "699d1f29d7b8c55300bb1fd2", "", "6749daeea367d0e9809e2dc2f309e6e3", "",
     "d60c74d2517fde4a74e0cd4709ed43a9"),
    # {256, 96, 128, 0, 128}
    ("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
     "0d18e06c7c725ac9e362e1ce", "2db5168e932556f8089a0622981d017d", "",
     "fa4362189661d163fcd6a56d8bf0405a", "d636ac1bbedd5cc3ee727dc2ab4a9489"),
    ("460fc864972261c2560e1eb88761ff1c992b982497bd2ac36c04071cbb8e5d99",
     "8a4a16b9e210eb68bcb6f58d", "99e4e926ffe927f691893fb79a96b067", "",
     "133fc15751621b5f325c7ff71ce08324", "ec4e87e0cf74a13618d0b68636ba9fa7"),
    # {256, 96, 408, 160, 128}
    ("24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
     "9ff18563b978ec281b3f2794",
     "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c",
     "adb5ec720ccf9898500028bf34afccbcaca126ef",
     "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8",
     "bc95c532fecc594c36d1550286a7a3f0"),
    # {256, 96, 104, 0, 128}
    ("82c4f12eeec3b2d3d157b0f992d292b237478d2cecc1d5f161389b97f999057a",
     "7b40b20f5f397177990ef2d1", "982a296ee1cd7086afad976945", "",
     "ec8e05a0471d6b43a59ca5335f", "113ddeafc62373cac2f5951bb9165249"),
    ("db4340af2f835a6c6d7ea0ca9d83ca81ba02c29b7410f221cb6071114e393240",
     "40e438357dd80a85cac3349e", "8ddb3397bd42853193cb0f80c9", "",
     "b694118c85c41abf69e229cb0f", "c07f1b8aafbd152f697eb67f2a85fe45"),
]


def main() -> None:
    ok = 0
    for i, (key, iv, pt, aad, ct, tag) in enumerate(VECTORS):
        k, n, p, a = (bytes.fromhex(x) for x in (key, iv, pt, aad))
        assert len(k) == 32 and len(n) == 12, f"vec {i}: bad key/nonce size"
        out = AESGCM(k).encrypt(n, p, a if a else None)
        assert out[:-16] == bytes.fromhex(ct), f"vec {i}: ct mismatch"
        assert out[-16:] == bytes.fromhex(tag), f"vec {i}: tag mismatch"
        ok += 1
        print(f"vec {i}: OK  pt={len(p):3d}B aad={len(a):3d}B")
    print(f"all {ok}/{len(VECTORS)} CAVP vectors reproduced")


if __name__ == "__main__":
    main()