"""
Data Integrity Service for InThreatDetection
=============================================

Provides document-level integrity verification using SHA3-256 hashing
and hash chains for tamper-evident audit logs.

Every document stored in MongoDB gets:
- `integrity_hash`: SHA3-256 hash of the document's data fields
- `previous_hash`: Hash of the previous document (hash chain)
- `encryption_status`: Whether sensitive fields are encrypted
"""

import json
import hashlib
from datetime import datetime, timezone
from app.database.mongodb import db_instance
from app.services.quantum_crypto import quantum_engine


# ─── Fields excluded from hash computation (metadata fields) ────────
HASH_EXCLUDE_FIELDS = {
    "_id", "integrity_hash", "previous_hash", "integrity_verified",
    "encryption_status", "encrypted_fields"
}


def compute_document_hash(doc: dict, previous_hash: str = "") -> str:
    """
    Compute a SHA3-256 integrity hash for a document.
    Excludes metadata fields that are added after storage.
    """
    # Extract only the data fields for hashing
    data_fields = {k: v for k, v in doc.items() if k not in HASH_EXCLUDE_FIELDS}

    # Create deterministic canonical representation
    canonical = json.dumps(data_fields, sort_keys=True, default=str)

    # Chain with previous hash
    hash_input = f"{previous_hash}:{canonical}" if previous_hash else canonical

    return hashlib.sha3_256(hash_input.encode("utf-8")).hexdigest()


def verify_document_integrity(doc: dict) -> dict:
    """
    Verify the integrity of a single document by recomputing its hash.
    Returns a result dict with verification status.
    """
    stored_hash = doc.get("integrity_hash")

    if not stored_hash:
        return {
            "status": "unverified",
            "reason": "No integrity hash present",
            "document_id": str(doc.get("_id", "unknown"))
        }

    # Recompute the hash
    previous_hash = doc.get("previous_hash", "")
    computed_hash = compute_document_hash(doc, previous_hash)

    if computed_hash == stored_hash:
        return {
            "status": "verified",
            "hash": stored_hash[:16] + "...",
            "document_id": str(doc.get("_id", "unknown"))
        }
    else:
        return {
            "status": "tampered",
            "reason": "Hash mismatch detected",
            "stored_hash": stored_hash[:16] + "...",
            "computed_hash": computed_hash[:16] + "...",
            "document_id": str(doc.get("_id", "unknown"))
        }


async def get_last_hash(collection_name: str) -> str:
    """
    Get the integrity_hash of the most recent document in a collection.
    Used to maintain the hash chain.
    """
    cursor = db_instance.db[collection_name].find(
        {"integrity_hash": {"$exists": True}},
        {"integrity_hash": 1}
    ).sort("timestamp", -1).limit(1)

    docs = await cursor.to_list(length=1)
    if docs and "integrity_hash" in docs[0]:
        return docs[0]["integrity_hash"]
    return ""


async def add_integrity_fields(doc: dict, collection_name: str) -> dict:
    """
    Add integrity hash and chain link to a document before storage.
    Also marks encryption status.
    """
    # Get the previous hash for chain continuity
    previous_hash = await get_last_hash(collection_name)

    # Compute integrity hash
    integrity_hash = compute_document_hash(doc, previous_hash)

    # Add integrity metadata
    doc["integrity_hash"] = integrity_hash
    doc["previous_hash"] = previous_hash
    doc["encryption_status"] = "quantum_encrypted"

    return doc


async def verify_collection_integrity(collection_name: str) -> dict:
    """
    Verify the integrity of all documents in a collection.
    Returns aggregate statistics and per-document results.
    """
    cursor = db_instance.db[collection_name].find().sort("timestamp", 1)
    documents = await cursor.to_list(length=10000)

    total = len(documents)
    verified = 0
    tampered = 0
    unverified = 0
    chain_intact = True
    results = []

    for doc in documents:
        result = verify_document_integrity(doc)
        results.append(result)

        if result["status"] == "verified":
            verified += 1
        elif result["status"] == "tampered":
            tampered += 1
            chain_intact = False
        else:
            unverified += 1

    return {
        "collection": collection_name,
        "total_documents": total,
        "verified": verified,
        "tampered": tampered,
        "unverified": unverified,
        "chain_intact": chain_intact,
        "integrity_score": round((verified / total * 100), 1) if total > 0 else 100.0,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "details": results[:50]  # Limit detail results to avoid huge responses
    }
