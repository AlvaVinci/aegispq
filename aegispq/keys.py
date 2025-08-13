import os, getpass, json
from .crypto import kem_generate, dsa_generate, save_secret, b64e

def init_keys(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    kem_pk, kem_sk = kem_generate("ML-KEM-768")
    dsa_pk, dsa_sk = dsa_generate("ML-DSA-65")
    pw = getpass.getpass("Passphrase for secret keys: ").encode()
    save_secret(os.path.join(out_dir, "kem.secret"), kem_sk, pw)
    save_secret(os.path.join(out_dir, "dsa.secret"), dsa_sk, pw)
    json.dump({"version":"0.1","kem_alg":"ML-KEM-768","dsa_alg":"ML-DSA-65",
               "kem_pk": b64e(kem_pk), "dsa_pk": b64e(dsa_pk)}, open(os.path.join(out_dir, "public.json"),"w"))
    return out_dir
