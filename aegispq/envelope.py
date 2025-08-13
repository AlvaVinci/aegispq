import json
from .crypto import b64e, b64d, aes_gcm_encrypt, aes_gcm_decrypt, kem_encapsulate, kem_decapsulate, dsa_sign, dsa_verify

VERSION = "0.1"

def build_envelope(plaintext, kem_pk, kem_alg, sender_dsa_pk, signer_sk, dsa_alg):
    kem_ct, shared = kem_encapsulate(kem_pk, kem_alg); aes_key = shared[:32]
    nonce, ct, tag = aes_gcm_encrypt(aes_key, plaintext)
    env = {"version": VERSION, "kem_alg": kem_alg, "dsa_alg": dsa_alg,
           "kem_ct": b64e(kem_ct), "nonce": b64e(nonce), "tag": b64e(tag),
           "ciphertext": b64e(ct), "sender_dsa_pk": b64e(sender_dsa_pk) if sender_dsa_pk else None, "meta": {}}
    if signer_sk:
        to_sign = json.dumps(env, sort_keys=True).encode()
        env["signature"] = b64e(dsa_sign(to_sign, signer_sk, dsa_alg))
    return env

def open_envelope(env, kem_sk):
    shared = kem_decapsulate(b64d(env["kem_ct"]), kem_sk, env["kem_alg"]); aes_key = shared[:32]
    pt = aes_gcm_decrypt(aes_key, b64d(env["nonce"]), b64d(env["ciphertext"]), b64d(env["tag"]))
    sig_ok = None
    if env.get("signature") and env.get("sender_dsa_pk"):
        to_verify = json.dumps({k:v for k,v in env.items() if k!="signature"}, sort_keys=True).encode()
        sig_ok = dsa_verify(to_verify, b64d(env["signature"]), b64d(env["sender_dsa_pk"]), env["dsa_alg"])
    return pt, sig_ok
