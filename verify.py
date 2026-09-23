#!/usr/bin/env python3
"""
Standalone Verifiable Presentation verifier for Delegate credentials & actions.
Runs independently without a server, database, or network connection.

Usage:
    python verify.py bundle.json
"""

import sys
import json
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonicalize(obj) -> bytes:
    """Serialize JSON with sorted keys, no whitespace, UTF-8 encoded."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def verify_ed25519(public_key_hex: str, signature_hex: str, payload: dict) -> bool:
    """Verifies Ed25519 signature against canonicalized payload."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        canonical_data = canonicalize(payload)
        public_key.verify(sig_bytes, canonical_data)
        return True
    except Exception as e:
        print(f"  [!] Signature verification exception: {e}")
        return False


def parse_iso(dt_str: str) -> datetime:
    dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_bundle(file_path: str) -> bool:
    print(f"=== Delegate Standalone Verifier ===")
    print(f"Loading presentation bundle: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load JSON file: {e}")
        return False

    action_req = bundle.get("action_request")
    agent_pub_key = bundle.get("agent_public_key")
    cred_chain = bundle.get("credential_chain", [])

    if not action_req or not agent_pub_key or not cred_chain:
        print("❌ Invalid bundle schema: missing action_request, agent_public_key, or credential_chain.")
        return False

    print(f"\n1. Verifying Credential Chain ({len(cred_chain)} link(s))...")

    # Index credentials by ID
    cred_map = {c["id"]: c for c in cred_chain}
    target_cred_id = action_req["credential_id"]

    if target_cred_id not in cred_map:
        print(f"❌ Target credential ID '{target_cred_id}' not found in credential chain.")
        return False

    leaf_cred = cred_map[target_cred_id]

    # Walk chain from leaf to root
    current = leaf_cred
    prev_child = None

    while current:
        cred_id = current["id"]
        issuer_pub_key = current.get("issuer_public_key")
        sig = current.get("signature")

        if not issuer_pub_key or not sig:
            print(f"❌ Credential '{cred_id}' missing issuer_public_key or signature.")
            return False

        # Reconstruct canonical credential payload
        cred_payload = {
            "id": cred_id,
            "issuer_principal_id": current["issuer_principal_id"],
            "subject_agent_id": current["subject_agent_id"],
            "parent_credential_id": current["parent_credential_id"],
            "action_types": sorted(current["action_types"]),
            "categories": sorted(current["categories"]),
            "max_amount_per_action": float(current["max_amount_per_action"]),
            "max_amount_cumulative": float(current["max_amount_cumulative"]),
            "currency": current["currency"],
            "valid_from": current["valid_from"],
            "valid_until": current["valid_until"],
            "allow_sub_delegation": current["allow_sub_delegation"],
        }

        # Verify signature
        if not verify_ed25519(issuer_pub_key, sig, cred_payload):
            print(f"❌ Invalid issuer signature on credential '{cred_id}'.")
            return False
        print(f"  ✓ Credential '{cred_id}' issuer signature valid.")

        # Scope subset check relative to child (if sub-delegated)
        if prev_child:
            if not set(prev_child["categories"]).issubset(set(current["categories"])):
                print(f"❌ Child credential categories exceed parent '{cred_id}' scope.")
                return False
            if not set(prev_child["action_types"]).issubset(set(current["action_types"])):
                print(f"❌ Child credential action_types exceed parent '{cred_id}' scope.")
                return False
            if float(prev_child["max_amount_per_action"]) > float(current["max_amount_per_action"]):
                print(f"❌ Child max_amount_per_action exceeds parent '{cred_id}'.")
                return False
            if not current.get("allow_sub_delegation", False):
                print(f"❌ Parent credential '{cred_id}' does not allow sub-delegation.")
                return False
            print(f"  ✓ Sub-delegation bounds check against parent '{cred_id}' valid.")

        parent_id = current.get("parent_credential_id")
        if parent_id:
            if parent_id not in cred_map:
                print(f"❌ Parent credential '{parent_id}' missing from chain bundle.")
                return False
            prev_child = current
            current = cred_map[parent_id]
        else:
            current = None

    print("\n2. Verifying Action Scope & Parameters...")
    action_type = action_req["action_type"]
    details = action_req["details"]
    category = details.get("category")
    amount = float(details.get("amount", 0.0))

    if action_type not in leaf_cred["action_types"]:
        print(f"❌ Action type '{action_type}' not allowed in credential scope {leaf_cred['action_types']}.")
        return False
    print(f"  ✓ Action type '{action_type}' within allowed list.")

    if category not in leaf_cred["categories"]:
        print(f"❌ Category '{category}' not allowed in credential scope {leaf_cred['categories']}.")
        return False
    print(f"  ✓ Category '{category}' within allowed categories.")

    if amount > float(leaf_cred["max_amount_per_action"]):
        print(f"❌ Amount ${amount} exceeds max per action limit ${leaf_cred['max_amount_per_action']}.")
        return False
    print(f"  ✓ Amount ${amount} <= max_amount_per_action ${leaf_cred['max_amount_per_action']}.")

    print("\n3. Verifying Agent Signature on Action Request...")
    action_payload = {
        "id": action_req["id"],
        "agent_id": action_req["agent_id"],
        "credential_id": action_req["credential_id"],
        "action_type": action_req["action_type"],
        "details": action_req["details"],
        "timestamp": action_req["timestamp"]
    }

    if not verify_ed25519(agent_pub_key, action_req["agent_signature"], action_payload):
        print("❌ Invalid agent signature on action request.")
        return False
    print("  ✓ Agent Ed25519 signature valid.")

    print("\n==============================================")
    print("✅ VERIFICATION SUCCESSFUL: Presentation Bundle is Cryptographically Valid!")
    print("==============================================\n")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify.py <path_to_bundle.json>")
        sys.exit(1)

    filepath = sys.argv[1]
    success = verify_bundle(filepath)
    sys.exit(0 if success else 1)
