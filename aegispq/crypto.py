import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt

# liboqs bindings (install one of: oqs or pqcow-liboqs)
_oqs = None; _err = None
for name in ("oqs", "liboqs", "pqcow_liboqs"):
    try:
        _oqs = __import__(name); break
    except Exception as e:
        _err = e

def _need_oqs():
    if _oqs is None: raise RuntimeError("liboqs bindings not found. Install 'oqs' or 'pqcow-liboqs'. Error: %r" % (_err,))

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)

def aes_gcm_encrypt(key, pt):
    nonce = get_random_bytes(12); c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt); return nonce, ct, tag

def aes_gcm_decrypt(key, nonce, ct, tag):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce); return c.decrypt_and_verify(ct, tag)

def kdf(pw, salt, dklen=32): return scrypt(pw, salt, dklen, N=2**15, r=8, p=1)

def kem_generate(alg="ML-KEM-768"):
    _need_oqs(); 
    with _oqs.KeyEncapsulation(alg) as kem: return kem.generate_keypair()

def kem_encapsulate(pk, alg="ML-KEM-768"):
    _need_oqs(); 
    with _oqs.KeyEncapsulation(alg) as kem: return kem.encap_secret(pk)

def kem_decapsulate(ct, sk, alg="ML-KEM-768"):
    _need_oqs(); 
    with _oqs.KeyEncapsulation(alg) as kem: kem.import_secret_key_bytes(sk); return kem.decap_secret(ct)

def dsa_generate(alg="ML-DSA-65"):
    _need_oqs(); 
    with _oqs.Signature(alg) as dsa: return dsa.generate_keypair()

def dsa_sign(msg, sk, alg="ML-DSA-65"):
    _need_oqs(); 
    with _oqs.Signature(alg) as dsa: dsa.import_secret_key_bytes(sk); return dsa.sign(msg)

def dsa_verify(msg, sig, pk, alg="ML-DSA-65"):
    _need_oqs(); 
    with _oqs.Signature(alg) as dsa: return dsa.verify(msg, sig, pk)

def save_secret(path, sk, pw):
    salt = get_random_bytes(16); key = kdf(pw, salt); nonce, ct, tag = aes_gcm_encrypt(key, sk)
    open(path,"wb").write(b"PQK1"+salt+nonce+tag+ct)

def load_secret(path, pw):
    blob = open(path,"rb").read(); assert blob[:4]==b"PQK1"
    salt, nonce, tag, ct = blob[4:20], blob[20:32], blob[32:48], blob[48:]
    key = kdf(pw, salt); return aes_gcm_decrypt(key, nonce, ct, tag)
