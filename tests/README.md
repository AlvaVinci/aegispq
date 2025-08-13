# AegisPQ Tests

This folder contains basic smoke tests for AegisPQ.

## Running Tests

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest
```

Example output:
```
================= test session starts =================
collected 3 items

tests/test_encryption.py ...                        [100%]

================== 3 passed in 0.50s =================
```

## Test Coverage

These tests verify:
- **Kyber KEM** key generation and encapsulation/decapsulation
- **AES-256-GCM** encryption/decryption
- **Optional Dilithium** signing and verification
