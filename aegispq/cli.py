import argparse, json, os, getpass
from .crypto import load_secret, b64d
from .envelope import build_envelope, open_envelope

def cmd_init(args):
    from .keys import init_keys
    print(f"Keys created under {init_keys(args.dir)}")

def cmd_encrypt(args):
    pub = json.load(open(args.recipient))
    kem_pk = b64d(pub["kem_pk"]); kem_alg = pub["kem_alg"]; dsa_alg = pub["dsa_alg"]
    data = open(args.input, "rb").read()
    sender_pk = None; signer_sk = None
    if args.signer:
        sender_pk = b64d(json.load(open(args.signer))["dsa_pk"])
    if args.signsec:
        pw = getpass.getpass("Passphrase for sender dsa.secret: ").encode()
        signer_sk = load_secret(args.signsec, pw)
    env = build_envelope(data, kem_pk, kem_alg, sender_pk, signer_sk, dsa_alg)
    if args.meta_ext:
        env.setdefault("meta", {})["orig_ext"] = os.path.splitext(args.input)[1]
    out = args.output or (os.path.basename(args.input)+".pq")
    open(out, "wb").write(json.dumps(env).encode()); print(f"Encrypted → {out}")

def cmd_decrypt(args):
    env = json.loads(open(args.input, "rb").read())
    pw = getpass.getpass("Passphrase for recipient kem.secret: ").encode()
    kem_sk = load_secret(args.kemsec, pw); plaintext, sig_ok = open_envelope(env, kem_sk)
    out = args.output or ("output"+env.get("meta",{}).get("orig_ext",""))
    open(out, "wb").write(plaintext); print(f"Decrypted → {out}")
    if sig_ok is not None: print("Signature:", "valid" if sig_ok else "INVALID")

def main():
    ap = argparse.ArgumentParser(prog="aegispq", description="AegisPQ: PQ file encryption (MVP)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p=sub.add_parser("init"); p.add_argument("--dir", default="keys"); p.set_defaults(func=cmd_init)
    p=sub.add_parser("encrypt"); p.add_argument("-r","--recipient", required=True); p.add_argument("-in","--input", required=True)
    p.add_argument("-out","--output"); p.add_argument("--signer"); p.add_argument("--signsec"); p.add_argument("--meta-ext", action="store_true"); p.set_defaults(func=cmd_encrypt)
    p=sub.add_parser("decrypt"); p.add_argument("-in","--input", required=True); p.add_argument("--kemsec", default="keys/kem.secret"); p.add_argument("-out","--output"); p.set_defaults(func=cmd_decrypt)
    args = ap.parse_args(); args.func(args)

if __name__ == "__main__":
    main()
