
# AegisPQ

Post-Quantum file encryption using **ML-KEM (Kyber)** + **AES-256-GCM** and optional **ML-DSA (Dilithium)** signatures via liboqs.

> **Status:** MVP for evaluation and testing — *Not yet security-audited*. Do not use for sensitive production data without review.

---

## Overview

AegisPQ is a command-line tool and Python library for encrypting files with *post-quantum cryptography (PQC)*.
It combines:

- **ML-KEM-768** (Kyber-768) for key encapsulation (NIST PQC standard candidate)
- **AES-256-GCM** for authenticated symmetric encryption
- **ML-DSA-65** (Dilithium-3) for optional digital signatures

**Why PQC?**  
Once large-scale quantum computers become practical, RSA/ECC encryption will be breakable.  
PQC algorithms are designed to resist such attacks, ensuring long-term confidentiality.

---

## Features

- **Post-Quantum Secure**: Based on NIST PQC finalists
- **Hybrid Encryption Envelope**: KEM (Kyber) + AES-GCM
- **Optional Signatures**: Sender authenticity via Dilithium
- **CLI & Python API**: Use from terminal or integrate into applications
- **Metadata Support**: Preserve file extension for easier recovery
- **Passphrase-Protected Keys**: Encrypted private keys with Scrypt + AES-GCM

---

## Installation

Requirements: Python 3.9+, pip, [liboqs Python bindings](https://github.com/open-quantum-safe/liboqs-python)

```bash
# Clone
git clone https://github.com/USERNAME/AegisPQ.git
cd AegisPQ

# Install dependencies
pip install -r requirements.txt

# Install liboqs bindings (choose one)
pip install oqs              # Official Python wrapper
# OR
pip install pqcow-liboqs     # Community wheels
```

---

## CLI Usage

### 1. Generate Key Pair
```bash
aegispq init --dir keys
```
Creates:
- `keys/public.json` — Public keys (shareable)
- `keys/kem.secret` — Kyber private key (passphrase protected)
- `keys/dsa.secret` — Dilithium signing key (passphrase protected)

### 2. Encrypt a File
```bash
aegispq encrypt -r keys/public.json -in message.txt -out message.pq --meta-ext
```
Options:
- `--meta-ext`: Save original file extension in the envelope

### 3. Decrypt a File
```bash
aegispq decrypt -in message.pq -out recovered.txt --kemsec keys/kem.secret
```

### 4. Sign and Encrypt
```bash
aegispq encrypt -r recipient_pub.json -in contract.pdf -out contract.pq     --signer my_public.json --signsec my/dsa.secret --meta-ext
```

---

## Python API Example

```python
from aegispq.crypto import kem_generate, aes_gcm_encrypt, aes_gcm_decrypt

# Generate Kyber key pair
pk, sk = kem_generate()

# Symmetric encryption
key = b'0'*32
nonce, ct, tag = aes_gcm_encrypt(key, b"hello world")
pt = aes_gcm_decrypt(key, nonce, ct, tag)
print(pt)
```

---

## Algorithm Details

| Component   | Algorithm         | Purpose                   |
|-------------|-------------------|---------------------------|
| KEM         | ML-KEM-768 (Kyber) | Post-quantum key exchange |
| Symmetric   | AES-256-GCM        | Authenticated encryption  |
| Signature   | ML-DSA-65          | Post-quantum signatures   |
| KDF         | Scrypt             | Derive key from passphrase|

---

## Security Notes

- **MVP status**: No independent security audit has been performed yet.
- **Not hybrid with classical ECC/RSA** in current MVP — consider adding for transitional deployments.
- Secrets are stored encrypted with AES-256-GCM using a passphrase-derived key via Scrypt.
- Metadata leakage: Filenames are not encrypted, but original extension may be stored if `--meta-ext` is used.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
