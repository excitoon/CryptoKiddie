#!/usr/bin/env python3
"""Independently verify the GOST-2012-256 signature in a CMS produced by the bridge.

Decisive diagnostic: is our CMS cryptographically valid (so any ESIA rejection is
account-linking/policy), or is the signature itself wrong (a bug to fix)?
"""
import sys
from asn1crypto import cms, core, x509
import gostcrypto

der = open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/cms.der", "rb").read()
ci = cms.ContentInfo.load(der)
sd = ci["content"]
si = sd["signer_infos"][0]

# Embedded signer certificate (scan DER for GOST pubkey: BIT STRING -> OCTET STRING 0x04 0x40)
cert_der = sd["certificates"][0].chosen.dump()
# pattern: 03 42 00 04 40 <64 bytes>  (BIT STRING len66, unused0, OCTET STRING len64)
p = cert_der.find(b"\x03\x42\x00\x04\x40")
if p < 0:
    p = cert_der.find(b"\x04\x40")
    pub64 = cert_der[p + 2: p + 2 + 64]
else:
    pub64 = cert_der[p + 5: p + 5 + 64]
print("pubkey inner len:", len(pub64))

# signedAttrs: must be re-encoded with explicit SET OF tag (0x31) for the hash
signed_attrs = si["signed_attrs"]
attrs_der = signed_attrs.dump()
# asn1crypto gives implicit [0] context tag (0xA0); replace first byte with 0x31
attrs_set = b"\x31" + attrs_der[1:]

sig = si["signature"].native
print("signature len:", len(sig))

digest_algo = si["digest_algorithm"]["algorithm"].native
print("digest algo:", digest_algo)

# Streebog-256 of the signed attributes
h = gostcrypto.gosthash.new("streebog256", data=attrs_set)
digest = h.digest()
print("attr digest:", digest.hex())

# Also: messageDigest attr value (hash of eContent)
for a in signed_attrs:
    if a["type"].native == "message_digest":
        md = a["values"][0].native
        print("messageDigest attr:", md.hex())

curve = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019["id-tc26-gost-3410-2012-256-paramSetB"]
signer = gostcrypto.gostsignature.new(
    gostcrypto.gostsignature.MODE_256, curve)

def try_verify(label, pubkey, signature, dgst):
    try:
        ok = signer.verify(pubkey, dgst, bytearray(signature))
        print(f"  {label}: {'VALID' if ok else 'invalid'}")
        return ok
    except Exception as e:
        print(f"  {label}: error {e}")
        return False

# GOST pubkey point: X||Y little-endian (each 32). gostcrypto expects public_key
# as bytearray of the point; try multiple conventions.
pubA = bytearray(pub64)               # as-is (X_le||Y_le)
pubB = bytearray(pub64[::-1])         # fully reversed
pubC = bytearray(pub64[:32][::-1] + pub64[32:][::-1])  # each half reversed

# Streebog digest byte orders
dg_as = bytearray(digest)
dg_rev = bytearray(digest[::-1])

# Signature byte orders
sg_as = bytes(sig)
sg_rev = bytes(sig[::-1])
sg_swap = bytes(sig[32:] + sig[:32])

print("verify attempts (pubkey x digest x sig):")
for pl, pk in [("pub-asis", pubA), ("pub-rev", pubB), ("pub-halfrev", pubC)]:
    for dl, dg in [("dg-asis", dg_as), ("dg-rev", dg_rev)]:
        for sl, sg2 in [("sig-asis", sg_as), ("sig-rev", sg_rev), ("sig-swap", sg_swap)]:
            try:
                if signer.verify(pk, dg, bytearray(sg2)):
                    print(f"  MATCH: {pl} {dl} {sl}")
            except Exception:
                pass
print("done")
