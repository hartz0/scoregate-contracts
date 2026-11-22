#!/usr/bin/env python3
"""Build a signed `ScoreAttestationInput` for `submit_score`, for isolated-deployment drills.

The attestation layout is specified in docs/attestation-spec.md (section 3): a SHA-256 commitment
over a 211-byte preimage, signed with secp256k1 over that digest (no further hashing), with the
recovery id in byte 64 of the signature. This script uses only the Python standard library.

    ATTESTATION_SIGNING_KEY_FILE=/path/to/key.hex \\
      scripts/build_attestation_fixture.py --contract C... --wallet G... --pair INJ_TEST \\
        --score 50 --timestamp 1700000000 --confidence 80 --model-version 1 \\
        --contract-version 4 --nonce 0 --network testnet

The signing key is read from the file named by ATTESTATION_SIGNING_KEY_FILE (64 hex characters),
never from the command line, and is never printed. The JSON on stdout is the value for
`--attestation-input`.

    --print-pubkey   print the signing key's public key as hex, compressed on the first line and
                     uncompressed on the second, to compare with `get_service_pubkey`
    --self-test      check the preimage against the golden digest pinned in
                     contracts/scoregate-score/src/test_attestation_domain_compat.rs, and the
                     signer against a published RFC 6979 vector
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys

# secp256k1 domain parameters.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

NETWORK_PASSPHRASES = {
    "testnet": "Test SDF Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
    "mainnet": "Public Global Stellar Network ; September 2015",
}

PREIMAGE_LEN = 211


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(k, point):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def point_from_x(x, odd):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise ValueError("x is not on the curve")
    return (x, y if (y & 1) == odd else P - y)


def compress(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def rfc6979_k(secret, digest):
    """Deterministic nonce (RFC 6979, HMAC-SHA256, 256-bit curve order)."""
    x = secret.to_bytes(32, "big")
    h1 = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_prehash(secret, digest):
    """Returns (r, s, recovery_id) over a 32-byte digest, with s in the lower half of the order
    (the host rejects high-s signatures)."""
    z = int.from_bytes(digest, "big")
    k = rfc6979_k(secret, digest)
    rx, ry = point_mul(k, G)
    r = rx % N
    s = pow(k, -1, N) * (z + r * secret) % N
    recovery_id = (ry & 1) | (2 if rx >= N else 0)
    if s > N // 2:
        s = N - s
        recovery_id ^= 1
    if r == 0 or s == 0 or recovery_id > 1:
        raise ValueError("unusable signature (recovery id above 1); use a different payload")
    return r, s, recovery_id


def recover(digest, r, s, recovery_id):
    z = int.from_bytes(digest, "big")
    big_r = point_from_x(r + (N if recovery_id & 2 else 0), recovery_id & 1)
    r_inv = pow(r, -1, N)
    q = point_add(point_mul(s * r_inv % N, big_r), point_mul((-z * r_inv) % N, G))
    return q


def strkey_payload(strkey):
    """The 32-byte payload of a G... or C... StrKey (checksum verified)."""
    raw = base64.b32decode(strkey + "=" * (-len(strkey) % 8))
    if len(strkey) != 56 or len(raw) != 35:
        raise ValueError("%r is not a 56-character StrKey address" % strkey)
    crc = 0
    for byte in raw[:-2]:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    if raw[-2:] != crc.to_bytes(2, "little"):
        raise ValueError("%r has a bad StrKey checksum" % strkey)
    return raw[1:33]


def preimage(wallet, pair, score, benford, ml, timestamp, confidence, model_version,
             contract, network_id, contract_id, contract_version):
    pair_bytes = pair.encode("ascii")
    if len(pair_bytes) > 9:
        raise ValueError("asset pair longer than 9 characters")
    buf = b"".join([
        wallet.encode("ascii"),
        pair_bytes.ljust(9, b"\x00"),
        score.to_bytes(4, "little"),
        bytes([1 if benford else 0, 1 if ml else 0]),
        timestamp.to_bytes(8, "little"),
        confidence.to_bytes(4, "little"),
        model_version.to_bytes(4, "little"),
        contract.encode("ascii"),
        network_id,
        contract_id,
        contract_version.to_bytes(4, "little"),
    ])
    if len(buf) != PREIMAGE_LEN:
        raise ValueError("preimage is %d bytes, expected %d" % (len(buf), PREIMAGE_LEN))
    return buf


def load_secret():
    path = os.environ.get("ATTESTATION_SIGNING_KEY_FILE")
    if not path:
        sys.exit("ATTESTATION_SIGNING_KEY_FILE must name a file holding the 64-hex-character signing key")
    with open(path, encoding="ascii") as handle:
        text = handle.read().strip()
    try:
        secret = int(text, 16)
    except ValueError:
        sys.exit("the signing key file must contain hexadecimal text")
    if len(text) != 64 or not 1 <= secret < N:
        sys.exit("the signing key must be 64 hex characters and a valid secp256k1 scalar")
    return secret


def self_test():
    golden = bytes([
        180, 179, 218, 207, 114, 222, 86, 231, 61, 229, 78, 206, 250, 240, 158, 39,
        21, 171, 10, 241, 232, 21, 243, 224, 225, 146, 248, 128, 119, 254, 100, 39,
    ])
    wallet = "G" + "A" * 55
    contract = "C" + "B" * 55
    digest = hashlib.sha256(preimage(
        wallet, "XLM_USDC", 42, True, False, 1_700_000_000, 90, 1,
        contract, bytes([9] * 32), bytes([7] * 32), 4)).digest()
    assert digest == golden, "preimage layout no longer matches the pinned golden digest"

    # RFC 6979 vector for secp256k1 / SHA-256: key 1, message "Satoshi Nakamoto".
    msg_digest = hashlib.sha256(b"Satoshi Nakamoto").digest()
    r, s, recovery_id = sign_prehash(1, msg_digest)
    assert r == 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8, "r mismatch"
    assert s == 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5, "s mismatch"
    assert recover(msg_digest, r, s, recovery_id) == G, "recovery did not return the public key"

    # Strkey checksum: the all-zero ed25519 account key has a well-known address.
    assert strkey_payload("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF") == bytes(32)
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--contract")
    parser.add_argument("--wallet")
    parser.add_argument("--pair")
    parser.add_argument("--score", type=int)
    parser.add_argument("--timestamp", type=int)
    parser.add_argument("--confidence", type=int)
    parser.add_argument("--model-version", type=int)
    parser.add_argument("--contract-version", type=int)
    parser.add_argument("--nonce", type=int)
    parser.add_argument("--network", default="testnet",
                        help="testnet, futurenet, mainnet, or a network passphrase")
    parser.add_argument("--benford-flag", action="store_true")
    parser.add_argument("--ml-flag", action="store_true")
    parser.add_argument("--print-pubkey", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    if args.print_pubkey:
        public = point_mul(load_secret(), G)
        print(compress(public).hex())
        print((b"" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")).hex())
        return

    required = ["contract", "wallet", "pair", "score", "timestamp", "confidence",
                "model_version", "contract_version", "nonce"]
    missing = [name for name in required if getattr(args, name) is None]
    if missing:
        parser.error("missing: " + ", ".join("--" + name.replace("_", "-") for name in missing))

    passphrase = NETWORK_PASSPHRASES.get(args.network, args.network)
    network_id = hashlib.sha256(passphrase.encode("utf-8")).digest()
    contract_id = strkey_payload(args.contract)
    strkey_payload(args.wallet)  # validates the checksum

    digest = hashlib.sha256(preimage(
        args.wallet, args.pair, args.score, args.benford_flag, args.ml_flag, args.timestamp,
        args.confidence, args.model_version, args.contract, network_id, contract_id,
        args.contract_version)).digest()
    r, s, recovery_id = sign_prehash(load_secret(), digest)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recovery_id])

    print(json.dumps({
        "attestation": {"Some": {
            "commitment": digest.hex(),
            "signature": signature.hex(),
            "contract_id": contract_id.hex(),
            "contract_version": args.contract_version,
            "nonce": args.nonce,
        }},
        "threshold_attestation": "None",
        "commitment": None,
    }))


if __name__ == "__main__":
    main()
