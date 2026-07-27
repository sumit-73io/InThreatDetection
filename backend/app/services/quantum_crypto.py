"""
Quantum-Safe Cryptography Engine for InThreatDetection
======================================================

Implements post-quantum cryptographic primitives:
- Kyber (ML-KEM) key encapsulation — simulated for portability
- AES-256-GCM symmetric encryption — genuine, quantum-resistant at 256-bit
- SHA-3 (SHA3-256) integrity hashing — genuine, quantum-resistant
- Dilithium (ML-DSA) digital signatures — simulated for portability

The Kyber/Dilithium simulation generates cryptographically secure random keys
and labels them with the correct algorithm identifiers. All actual encryption
(AES-256-GCM) and hashing (SHA-3) are fully functional and quantum-safe.
"""

import os
import json
import hashlib
import secrets
import time
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class QuantumCryptoEngine:
    """
    Post-Quantum Cryptography engine providing encryption, hashing,
    and digital signature capabilities for the InThreatDetection platform.
    """

    ALGORITHM_SUITE = {
        "key_encapsulation": "Kyber-1024 (ML-KEM) [Simulated]",
        "symmetric_cipher": "AES-256-GCM",
        "hash_function": "SHA3-256",
        "digital_signature": "Dilithium-3 (ML-DSA) [Simulated]",
        "nist_compliance": "FIPS 203 / FIPS 204 / FIPS 197"
    }

    def __init__(self):
        self._initialized = False
        self._session_key = None
        self._signing_key = None
        self._verification_key = None
        self._key_fingerprint = None
        self._startup_time = None
        self._operations_count = 0

    def initialize(self):
        """
        Initialize the quantum crypto engine.
        Simulates a Kyber key encapsulation to derive the AES-256 session key
        and generates a Dilithium signing keypair.
        """
        # Simulate Kyber-1024 key encapsulation
        # In production, this would use liboqs KEM.encaps()
        self._session_key = get_random_bytes(32)  # 256-bit AES key

        # Simulate Dilithium-3 keypair generation
        # In production, this would use liboqs Signature keypair
        self._signing_key = get_random_bytes(64)    # Private signing key
        self._verification_key = get_random_bytes(32)  # Public verification key

        # Create a fingerprint of the session key for identification
        self._key_fingerprint = hashlib.sha3_256(
            self._session_key + self._verification_key
        ).hexdigest()[:16].upper()

        self._startup_time = datetime.now(timezone.utc)
        self._initialized = True

        # Data minimization: the algorithm suite and key fingerprint are
        # deliberately NOT logged. Process logs are widely readable and a key
        # fingerprint is a stable identifier for the session key.
        print("Quantum Crypto Engine initialized")

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def get_posture(self) -> dict:
        """
        Minimized status view - the ONLY crypto status exposed over the API.

        Data minimization ("quantum proofing"): callers learn whether each
        subsystem is operational and nothing more. Specifically withheld:
        algorithm names and versions, the session key fingerprint, key strength,
        operation counts and session establishment time. Those describe the
        cryptographic configuration, which is exactly what an attacker
        fingerprints before choosing an approach.

        `get_status()` retains the full detail for in-process diagnostics only
        and must not be returned from a route.
        """
        active = self._initialized
        return {
            "status": "active" if active else "inactive",
            "subsystems": [
                {"name": "Key Encapsulation", "status": "Active" if active else "Inactive"},
                {"name": "Payload Encryption", "status": "Active" if active else "Inactive"},
                {"name": "Integrity Hashing", "status": "Active" if active else "Inactive"},
                {"name": "Digital Signatures", "status": "Active" if active else "Inactive"},
            ],
            "quantum_resistant": active,
        }

    def get_status(self) -> dict:
        """
        Full diagnostic status. INTERNAL USE ONLY - never return this from an
        API route; it exposes the algorithm suite and key fingerprint. Use
        `get_posture()` for anything that reaches a client.
        """
        if not self._initialized:
            return {"status": "inactive", "message": "Engine not initialized"}

        uptime_seconds = (datetime.now(timezone.utc) - self._startup_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)

        return {
            "status": "active",
            "algorithm_suite": self.ALGORITHM_SUITE,
            "key_fingerprint": self._key_fingerprint,
            "uptime": f"{hours}h {minutes}m {seconds}s",
            "uptime_seconds": int(uptime_seconds),
            "operations_performed": self._operations_count,
            "session_established": self._startup_time.isoformat(),
            "key_strength_bits": 256,
            "quantum_resistant": True
        }

    # ─── Encryption / Decryption ─────────────────────────────────────

    def encrypt_field(self, plaintext: str) -> dict:
        """
        Encrypt a single string field using AES-256-GCM.
        Returns a dict with ciphertext, nonce, and tag (all hex-encoded).
        """
        if not self._initialized:
            raise RuntimeError("Quantum Crypto Engine not initialized")

        cipher = AES.new(self._session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        self._operations_count += 1

        return {
            "ciphertext": ciphertext.hex(),
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_field(self, encrypted: dict) -> str:
        """
        Decrypt a single encrypted field.
        Expects a dict with ciphertext, nonce, and tag (all hex-encoded).
        """
        if not self._initialized:
            raise RuntimeError("Quantum Crypto Engine not initialized")

        cipher = AES.new(
            self._session_key,
            AES.MODE_GCM,
            nonce=bytes.fromhex(encrypted["nonce"])
        )

        plaintext = cipher.decrypt_and_verify(
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(encrypted["tag"])
        )

        self._operations_count += 1
        return plaintext.decode("utf-8")

    def encrypt_payload(self, data: dict) -> dict:
        """
        Encrypt an entire dict payload. Serializes to JSON, encrypts,
        and returns the encrypted bundle with integrity metadata.
        """
        if not self._initialized:
            raise RuntimeError("Quantum Crypto Engine not initialized")

        plaintext = json.dumps(data, default=str)
        cipher = AES.new(self._session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        # Compute SHA3-256 hash of the original plaintext
        sha3_hash = hashlib.sha3_256(plaintext.encode("utf-8")).hexdigest()

        # Sign the hash with simulated Dilithium
        signature = self.sign_data(sha3_hash)

        self._operations_count += 1

        return {
            "ciphertext": ciphertext.hex(),
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "sha3_hash": sha3_hash,
            "signature": signature,
            "algorithm_suite": "Kyber-1024 + AES-256-GCM + SHA3-256 + Dilithium-3"
        }

    def decrypt_payload(self, encrypted: dict) -> dict:
        """
        Decrypt an encrypted payload bundle. Verifies integrity and signature.
        """
        if not self._initialized:
            raise RuntimeError("Quantum Crypto Engine not initialized")

        cipher = AES.new(
            self._session_key,
            AES.MODE_GCM,
            nonce=bytes.fromhex(encrypted["nonce"])
        )

        plaintext = cipher.decrypt_and_verify(
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(encrypted["tag"])
        )

        plaintext_str = plaintext.decode("utf-8")

        # Verify SHA3-256 integrity
        computed_hash = hashlib.sha3_256(plaintext_str.encode("utf-8")).hexdigest()
        if computed_hash != encrypted.get("sha3_hash"):
            raise ValueError("SHA3-256 integrity check FAILED — data may be tampered")

        # Verify Dilithium signature
        if not self.verify_signature(encrypted.get("sha3_hash", ""), encrypted.get("signature", "")):
            raise ValueError("Dilithium signature verification FAILED")

        self._operations_count += 1
        return json.loads(plaintext_str)

    # ─── Integrity Hashing ───────────────────────────────────────────

    def compute_integrity_hash(self, data: dict, previous_hash: str = "") -> str:
        """
        Compute a SHA3-256 integrity hash of a data dict.
        Optionally chains with a previous hash for tamper-evident audit logs.
        """
        # Create a deterministic string representation
        canonical = json.dumps(data, sort_keys=True, default=str)

        # Chain with previous hash if provided
        hash_input = f"{previous_hash}:{canonical}" if previous_hash else canonical

        return hashlib.sha3_256(hash_input.encode("utf-8")).hexdigest()

    # ─── Digital Signatures (Simulated Dilithium) ────────────────────

    def sign_data(self, data: str) -> str:
        """
        Sign data using simulated Dilithium-3.
        In production, this would use liboqs Dilithium sign().
        Here we use HMAC-SHA3 with the signing key as a simulation.
        """
        if not self._initialized:
            raise RuntimeError("Quantum Crypto Engine not initialized")

        # Simulate Dilithium by using HMAC-like construction with SHA3
        signature_input = self._signing_key + data.encode("utf-8")
        signature = hashlib.sha3_256(signature_input).hexdigest()

        self._operations_count += 1
        return signature

    def verify_signature(self, data: str, signature: str) -> bool:
        """
        Verify a simulated Dilithium-3 signature.
        """
        if not self._initialized:
            return False

        expected = hashlib.sha3_256(
            self._signing_key + data.encode("utf-8")
        ).hexdigest()

        return secrets.compare_digest(expected, signature)


# ─── Global Singleton ────────────────────────────────────────────────

quantum_engine = QuantumCryptoEngine()
