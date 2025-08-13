# AegisPQ

> **⚠️ Security Notice:** This is an MVP (v0.1.0) for evaluation and testing. **Not yet security-audited**.  
> Do **NOT** use for sensitive production data without independent expert review.

**AegisPQ** is a Post-Quantum file encryption tool and Python library that combines:
- **ML-KEM (Kyber)** for key encapsulation (post-quantum key exchange)
- **AES-256-GCM** for authenticated symmetric encryption
- Optional **ML-DSA (Dilithium)** for digital signatures

---

## Overview

Once large-scale quantum computers become practical, RSA and ECC will be breakable.  
AegisPQ uses NIST PQC standard algorithms to ensure **long-term confidentiality** and **integrity**.

---

## Features

- **Post-Quantum Secure** — Based on NIST PQC algorithms
- **Hybrid Encryption Envelope** — Kyber KEM + AES-GCM
- **Optional Signatures** — Authenticate sender using Dilithium
- **CLI & Python API** — Works from terminal or in code
- **Passphrase-Protected Keys** — AES-256-GCM + Scrypt
- **Metadata Support** — Preserve file extension if desired

---

## Installation

**Requirements:** Python 3.9+, pip, [liboqs Python bindings](https://github.com/open-quantum-safe/liboqs-python)

```bash
# Clone the repository
git clone https://github.com/USERNAME/AegisPQ.git
cd AegisPQ

# Install Python dependencies
pip install -r requirements.txt

# Install liboqs Python bindings
pip install oqs              # Official bindings
# OR
pip install pqcow-liboqs     # Community-provided wheels
```

---

## CLI Usage

| Task               | Example Command |
|--------------------|-----------------|
| Generate key pair  | `aegispq init --dir keys` |
| Encrypt a file     | `aegispq encrypt -r keys/public.json -in message.txt -out message.pq --meta-ext` |
| Decrypt a file     | `aegispq decrypt -in message.pq -out recovered.txt --kemsec keys/kem.secret` |
| Sign & encrypt     | `aegispq encrypt -r recipient_pub.json -in contract.pdf -out contract.pq --signer my_public.json --signsec my/dsa.secret --meta-ext` |

---

## Python API Example

```python
from aegispq.crypto import kem_generate, aes_gcm_encrypt, aes_gcm_decrypt

# Generate Kyber key pair
pk, sk = kem_generate()

# Symmetric encryption
key = b'0' * 32
nonce, ct, tag = aes_gcm_encrypt(key, b"Hello PQC!")
print("Ciphertext:", ct)

# Decrypt
pt = aes_gcm_decrypt(key, nonce, ct, tag)
print("Recovered:", pt)
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

- **No independent audit** — MVP should not be used in production.
- Not hybrid with classical ECC/RSA (planned for future).
- Private keys are AES-256-GCM encrypted with Scrypt-derived keys.
- Filenames are not encrypted; use `--meta-ext` to store original extension securely.

---

## Contributing

Pull requests and issue reports are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
