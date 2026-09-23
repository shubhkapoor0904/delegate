#!/usr/bin/env python3
"""
CLI Scripted Demo for Delegate AI Agent Authorization Service.
Walks through steps 1-9 sequentially as specified in prompt.txt.
"""

import sys
import json
import subprocess
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.crypto import sign_payload

client = TestClient(app)


def print_step(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def main():
    print("Starting Delegate CLI Walkthrough Demo...\n")

    # Step 1: Register Principal and Agent
    print_step("Step 1: Register Principal 'priya' and Agent 'procurement-intake-agent-v1'")
    p_resp = client.post("/principals", json={"id": "priya", "name": "Priya Sharma"}).json()
    print(f"[+] Registered Principal: id={p_resp['id']}, name='{p_resp['name']}'")
    print(f"    Public Key:  {p_resp['public_key'][:20]}...")
    print(f"    Private Key: {p_resp['private_key'][:20]}... (kept client-side only)")

    a_resp = client.post("/agents", json={"id": "procurement-intake-agent-v1", "name": "Procurement Intake Agent v1"}).json()
    print(f"[+] Registered Agent:     id={a_resp['id']}, name='{a_resp['name']}'")
    print(f"    Public Key:  {a_resp['public_key'][:20]}...")
    print(f"    Private Key: {a_resp['private_key'][:20]}... (kept client-side only)")

    # Step 2: Issue Root Credential
    print_step("Step 2: Issue Root Credential")
    now = datetime.now(timezone.utc)
    valid_from = (now - timedelta(minutes=1)).isoformat()
    valid_until = (now + timedelta(days=90)).isoformat()

    cred_req = {
        "id": "cred-root-001",
        "issuer_principal_id": p_resp["id"],
        "subject_agent_id": a_resp["id"],
        "action_types": ["renew", "purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "currency": "USD",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "allow_sub_delegation": True,
        "issuer_private_key": p_resp["private_key"]
    }
    c_resp = client.post("/credentials", json=cred_req).json()
    print(f"[+] Issued Credential: id={c_resp['id']}")
    print(f"    Allowed Categories: {c_resp['categories']}")
    print(f"    Max Per Action:     ${c_resp['max_amount_per_action']:,.2f}")
    print(f"    Max Cumulative:     ${c_resp['max_amount_cumulative']:,.2f}")
    print(f"    Ed25519 Signature:  {c_resp['signature'][:24]}...")

    # Step 3: Submit Action: $3,200 SaaS renewal → Expect Approved
    print_step("Step 3: Submit Action Request ($3,200 SaaS Renewal)")
    act1_id = "act-saas-renewal-01"
    act1_timestamp = datetime.now(timezone.utc).isoformat()
    act1_details = {"category": "software", "amount": 3200.0, "vendor": "CloudSaaS Inc."}

    act1_payload = {
        "id": act1_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "renew",
        "details": act1_details,
        "timestamp": act1_timestamp
    }
    act1_sig = sign_payload(a_resp["private_key"], act1_payload)

    act1_req = {
        "id": act1_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "renew",
        "details": act1_details,
        "timestamp": act1_timestamp,
        "agent_signature": act1_sig
    }

    res1 = client.post("/actions", json=act1_req).json()
    print(f"[*] Action ID: {act1_id}")
    print(f"[*] Verdict:   {res1['verdict'].upper()}")
    print(f"[*] Reasons:   {res1['reasons']}")
    print(f"[*] Audit Record Hash: {res1['audit_record']['record_hash'][:24]}...")

    # Step 4: Submit Action: $6,000 → Expect Rejected (exceeds max_amount_per_action)
    print_step("Step 4: Submit Action Request ($6,000 Hardware/Software)")
    act2_id = "act-over-limit-02"
    act2_timestamp = datetime.now(timezone.utc).isoformat()
    act2_details = {"category": "software", "amount": 6000.0, "vendor": "Enterprise Tech"}

    act2_payload = {
        "id": act2_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "purchase",
        "details": act2_details,
        "timestamp": act2_timestamp
    }
    act2_sig = sign_payload(a_resp["private_key"], act2_payload)

    act2_req = {
        "id": act2_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "purchase",
        "details": act2_details,
        "timestamp": act2_timestamp,
        "agent_signature": act2_sig
    }

    res2 = client.post("/actions", json=act2_req).json()
    print(f"[*] Action ID: {act2_id}")
    print(f"[*] Verdict:   {res2['verdict'].upper()}")
    print(f"[*] Reasons:   {res2['reasons']}")

    # Step 5: Revoke Credential
    print_step("Step 5: Revoke Root Credential")
    rev_res = client.post(f"/credentials/{c_resp['id']}/revoke").json()
    print(f"[+] Revocation response: {rev_res}")

    # Step 6: Resubmit $3,200 action with new action_id → Expect Rejected (credential not active)
    print_step("Step 6: Resubmit $3,200 Action with New Action ID")
    act3_id = "act-saas-renewal-03"
    act3_timestamp = datetime.now(timezone.utc).isoformat()
    act3_details = {"category": "software", "amount": 3200.0, "vendor": "CloudSaaS Inc."}

    act3_payload = {
        "id": act3_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "renew",
        "details": act3_details,
        "timestamp": act3_timestamp
    }
    act3_sig = sign_payload(a_resp["private_key"], act3_payload)

    act3_req = {
        "id": act3_id,
        "agent_id": a_resp["id"],
        "credential_id": c_resp["id"],
        "action_type": "renew",
        "details": act3_details,
        "timestamp": act3_timestamp,
        "agent_signature": act3_sig
    }

    res3 = client.post("/actions", json=act3_req).json()
    print(f"[*] Action ID: {act3_id}")
    print(f"[*] Verdict:   {res3['verdict'].upper()}")
    print(f"[*] Reasons:   {res3['reasons']}")

    # Step 7: Print Audit Ledger & Chain Validity
    print_step("Step 7: Fetch Final Audit Ledger & Verify Hash Chain")
    audit_res = client.get("/audit").json()
    records = audit_res["records"]
    chain_valid = audit_res["chain_valid"]

    print(f"Total Audit Records: {len(records)}")
    for r in records:
        print(f"  Record #{r['id']} | Action: {r['action_id']} | Verdict: {r['verdict']} | PrevHash: {r['prev_hash'][:12]}... | RecordHash: {r['record_hash'][:12]}...")
    print(f"\n[✓] Audit Chain Valid: {chain_valid}")

    # Step 8: Export Approved Action as VerifiablePresentation Bundle to JSON
    print_step("Step 8: Export Verifiable Presentation Bundle to 'bundle.json'")
    bundle_data = {
        "action_request": act1_req,
        "agent_public_key": a_resp["public_key"],
        "credential_chain": [
            {
                "id": c_resp["id"],
                "issuer_principal_id": c_resp["issuer_principal_id"],
                "subject_agent_id": c_resp["subject_agent_id"],
                "parent_credential_id": c_resp["parent_credential_id"],
                "action_types": c_resp["action_types"],
                "categories": c_resp["categories"],
                "max_amount_per_action": c_resp["max_amount_per_action"],
                "max_amount_cumulative": c_resp["max_amount_cumulative"],
                "currency": c_resp["currency"],
                "valid_from": c_resp["valid_from"],
                "valid_until": c_resp["valid_until"],
                "allow_sub_delegation": c_resp["allow_sub_delegation"],
                "signature": c_resp["signature"],
                "issuer_public_key": p_resp["public_key"]
            }
        ]
    }

    with open("bundle.json", "w", encoding="utf-8") as f:
        json.dump(bundle_data, f, indent=2)
    print("[+] Exported 'bundle.json' successfully.")

    # Step 9: Run verify.py as a completely separate process
    print_step("Step 9: Run 'python verify.py bundle.json' in Separate Process")
    result = subprocess.run([sys.executable, "verify.py", "bundle.json"], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Stderr:", result.stderr)

    print("Demo completed successfully!")


if __name__ == "__main__":
    main()
