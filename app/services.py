import hashlib
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.models import Principal, Agent, Credential, ActionRequest, AuditRecord, current_iso_time
from app.crypto import canonicalize, sign_payload, verify_payload_signature, generate_keypair
from app.schemas import CredentialCreate, ActionRequestCreate


IN_MEMORY_KEY_STORE: Dict[str, str] = {}


def get_credential_payload(
    id: Optional[str],
    issuer_principal_id: str,
    subject_agent_id: str,
    parent_credential_id: Optional[str],
    action_types: List[str],
    categories: List[str],
    max_amount_per_action: float,
    max_amount_cumulative: float,
    currency: str,
    valid_from: str,
    valid_until: str,
    allow_sub_delegation: bool,
) -> Dict[str, Any]:
    """Builds canonical dictionary for signing / verifying credentials."""
    payload = {
        "issuer_principal_id": issuer_principal_id,
        "subject_agent_id": subject_agent_id,
        "parent_credential_id": parent_credential_id,
        "action_types": sorted(action_types),
        "categories": sorted(categories),
        "max_amount_per_action": float(max_amount_per_action),
        "max_amount_cumulative": float(max_amount_cumulative),
        "currency": currency,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "allow_sub_delegation": allow_sub_delegation,
    }
    if id:
        payload["id"] = id
    return payload


def get_action_request_payload(
    action_id: str,
    agent_id: str,
    credential_id: str,
    action_type: str,
    details: Dict[str, Any],
    timestamp: str
) -> Dict[str, Any]:
    """Builds canonical dictionary for signing / verifying action requests."""
    return {
        "id": action_id,
        "agent_id": agent_id,
        "credential_id": credential_id,
        "action_type": action_type,
        "details": details,
        "timestamp": timestamp
    }


def get_audit_record_payload(
    prev_hash: str,
    action_id: str,
    credential_id: str,
    verdict: str,
    reasons: List[str],
    cumulative_spend_after: float,
    created_at: str
) -> Dict[str, Any]:
    """Builds canonical dictionary for audit record hashing."""
    return {
        "prev_hash": prev_hash,
        "action_id": action_id,
        "credential_id": credential_id,
        "verdict": verdict,
        "reasons": sorted(reasons),
        "cumulative_spend_after": float(cumulative_spend_after),
        "created_at": created_at
    }


def parse_iso_datetime(dt_str: str) -> datetime:
    """Parses ISO 8601 string into timezone-aware datetime."""
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as e:
        raise ValueError(f"Invalid ISO datetime string '{dt_str}': {e}")


def validate_sub_delegation(
    child: CredentialCreate,
    parent: Credential
) -> None:
    """Validates that a child credential scope is a strict subset of parent credential."""
    if parent.status != "active":
        raise HTTPException(status_code=400, detail="Parent credential is not active")
    
    if not parent.allow_sub_delegation:
        raise HTTPException(status_code=400, detail="Parent credential does not allow sub-delegation")

    # Categories must be a subset of parent categories
    parent_categories = set(parent.categories)
    child_categories = set(child.categories)
    if not child_categories.issubset(parent_categories):
        raise HTTPException(
            status_code=400,
            detail=f"Child categories {child.categories} exceed parent categories {parent.categories}"
        )

    # Action types must be a subset of parent action types
    parent_action_types = set(parent.action_types)
    child_action_types = set(child.action_types)
    if not child_action_types.issubset(parent_action_types):
        raise HTTPException(
            status_code=400,
            detail=f"Child action_types {child.action_types} exceed parent action_types {parent.action_types}"
        )

    # Max amounts must not exceed parent
    if child.max_amount_per_action > parent.max_amount_per_action:
        raise HTTPException(
            status_code=400,
            detail=f"Child max_amount_per_action ({child.max_amount_per_action}) exceeds parent ({parent.max_amount_per_action})"
        )

    if child.max_amount_cumulative > parent.max_amount_cumulative:
        raise HTTPException(
            status_code=400,
            detail=f"Child max_amount_cumulative ({child.max_amount_cumulative}) exceeds parent ({parent.max_amount_cumulative})"
        )

    # Validity date range must fall within parent date range
    child_from = parse_iso_datetime(child.valid_from)
    child_until = parse_iso_datetime(child.valid_until)
    parent_from = parse_iso_datetime(parent.valid_from)
    parent_until = parse_iso_datetime(parent.valid_until)

    if child_from < parent_from or child_until > parent_until:
        raise HTTPException(
            status_code=400,
            detail="Child validity date range is outside parent validity date range"
        )


def revoke_credential_cascade(db: Session, credential_id: str) -> int:
    """Sets status = 'revoked' for credential and recursively for all descendants."""
    cred = db.query(Credential).filter(Credential.id == credential_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    revoked_count = 0
    to_revoke = [cred]

    while to_revoke:
        current = to_revoke.pop(0)
        if current.status != "revoked":
            current.status = "revoked"
            revoked_count += 1
            # Find children
            children = db.query(Credential).filter(Credential.parent_credential_id == current.id).all()
            to_revoke.extend(children)

    db.commit()
    return revoked_count


def verify_action_request(db: Session, request: ActionRequestCreate) -> Tuple[str, List[str], AuditRecord]:
    """
    Core verification engine. Executes 10 verification steps in order.
    Returns (verdict, reasons, audit_record).
    """
    reasons: List[str] = []
    verdict = "approved"

    # Step 1: Replay Protection - Reject if action_id was already seen
    existing_action = db.query(ActionRequest).filter(ActionRequest.id == request.id).first()
    existing_audit = db.query(AuditRecord).filter(AuditRecord.action_id == request.id).first()
    if existing_action or existing_audit:
        verdict = "rejected"
        reasons.append("Action ID already processed (replay attack detected)")

    # Step 2: Timestamp Freshness Check - Within 5 minutes
    if verdict == "approved":
        try:
            req_dt = parse_iso_datetime(request.timestamp)
            now_dt = datetime.now(timezone.utc)
            diff_seconds = abs((now_dt - req_dt).total_seconds())
            if diff_seconds > 300:
                verdict = "rejected"
                reasons.append("Timestamp is stale or in the future (> 5 minutes)")
        except Exception:
            verdict = "rejected"
            reasons.append("Invalid timestamp format")

    # Step 3: Load credential and verify issuer signature
    cred = None
    if verdict == "approved":
        cred = db.query(Credential).filter(Credential.id == request.credential_id).first()
        if not cred:
            verdict = "rejected"
            reasons.append("Credential not found")
        else:
            issuer = db.query(Principal).filter(Principal.id == cred.issuer_principal_id).first()
            if not issuer:
                verdict = "rejected"
                reasons.append("Issuer principal not found")
            else:
                payload = get_credential_payload(
                    cred.id, cred.issuer_principal_id, cred.subject_agent_id,
                    cred.parent_credential_id, cred.action_types, cred.categories,
                    cred.max_amount_per_action, cred.max_amount_cumulative, cred.currency,
                    cred.valid_from, cred.valid_until, cred.allow_sub_delegation
                )
                if not verify_payload_signature(issuer.public_key, cred.signature, payload):
                    verdict = "rejected"
                    reasons.append("Invalid issuer signature on credential")

    # Step 4: Reject if status != active or now outside valid_from/valid_until
    if verdict == "approved" and cred:
        if cred.status != "active":
            verdict = "rejected"
            reasons.append("credential not active")
        else:
            try:
                now_dt = datetime.now(timezone.utc)
                vf_dt = parse_iso_datetime(cred.valid_from)
                vu_dt = parse_iso_datetime(cred.valid_until)
                if now_dt < vf_dt or now_dt > vu_dt:
                    verdict = "rejected"
                    reasons.append("Current time is outside credential validity period")
            except Exception:
                verdict = "rejected"
                reasons.append("Credential validity date parsing error")

    # Step 5: Ancestor verification (defense in depth)
    if verdict == "approved" and cred and cred.parent_credential_id:
        curr_parent_id = cred.parent_credential_id
        child_ref = cred
        while curr_parent_id:
            parent_cred = db.query(Credential).filter(Credential.id == curr_parent_id).first()
            if not parent_cred:
                verdict = "rejected"
                reasons.append("Parent credential in ancestor chain not found")
                break
            if parent_cred.status != "active":
                verdict = "rejected"
                reasons.append("Ancestor credential is not active")
                break
            # Verify ancestor issuer signature
            p_issuer = db.query(Principal).filter(Principal.id == parent_cred.issuer_principal_id).first()
            if not p_issuer:
                verdict = "rejected"
                reasons.append("Ancestor issuer principal not found")
                break
            p_payload = get_credential_payload(
                parent_cred.id, parent_cred.issuer_principal_id, parent_cred.subject_agent_id,
                parent_cred.parent_credential_id, parent_cred.action_types, parent_cred.categories,
                parent_cred.max_amount_per_action, parent_cred.max_amount_cumulative, parent_cred.currency,
                parent_cred.valid_from, parent_cred.valid_until, parent_cred.allow_sub_delegation
            )
            if not verify_payload_signature(p_issuer.public_key, parent_cred.signature, p_payload):
                verdict = "rejected"
                reasons.append("Invalid signature on ancestor credential")
                break
            # Recheck child scope <= parent scope
            if not set(child_ref.categories).issubset(set(parent_cred.categories)):
                verdict = "rejected"
                reasons.append("Child credential categories exceed ancestor scope")
                break
            if not set(child_ref.action_types).issubset(set(parent_cred.action_types)):
                verdict = "rejected"
                reasons.append("Child credential action_types exceed ancestor scope")
                break
            if child_ref.max_amount_per_action > parent_cred.max_amount_per_action:
                verdict = "rejected"
                reasons.append("Child max_amount_per_action exceeds ancestor limit")
                break
            if child_ref.max_amount_cumulative > parent_cred.max_amount_cumulative:
                verdict = "rejected"
                reasons.append("Child max_amount_cumulative exceeds ancestor limit")
                break

            child_ref = parent_cred
            curr_parent_id = parent_cred.parent_credential_id

    # Step 6: Reject if action_type or category is out of scope
    category = request.details.get("category")
    if verdict == "approved" and cred:
        if request.action_type not in cred.action_types or category not in cred.categories:
            verdict = "rejected"
            reasons.append("Action type or category out of scope")

    # Step 7: Reject if amount > max_amount_per_action
    amount = float(request.details.get("amount", 0.0))
    if verdict == "approved" and cred:
        if amount > cred.max_amount_per_action:
            verdict = "rejected"
            reasons.append("exceeds max_amount_per_action")

    # Step 8: Reject if spent_so_far + amount > max_amount_cumulative
    if verdict == "approved" and cred:
        if (cred.spent_so_far + amount) > cred.max_amount_cumulative:
            verdict = "rejected"
            reasons.append("exceeds max_amount_cumulative")

    # Step 9: Verify agent's own signature on ActionRequest
    if verdict == "approved" and cred:
        agent = db.query(Agent).filter(Agent.id == request.agent_id).first()
        if not agent:
            verdict = "rejected"
            reasons.append("Agent not found")
        else:
            action_payload = get_action_request_payload(
                request.id, request.agent_id, request.credential_id,
                request.action_type, request.details, request.timestamp
            )
            if not request.agent_signature and request.agent_id in IN_MEMORY_KEY_STORE:
                agent_priv = IN_MEMORY_KEY_STORE[request.agent_id]
                request.agent_signature = sign_payload(agent_priv, action_payload)

            if not request.agent_signature or not verify_payload_signature(agent.public_key, request.agent_signature, action_payload):
                verdict = "rejected"
                reasons.append("Invalid agent signature on ActionRequest")

    # Step 10: Record Execution & Audit Ledger Hash Chaining
    # Save ActionRequest record if not existing
    if not existing_action:
        action_db_item = ActionRequest(
            id=request.id,
            agent_id=request.agent_id,
            credential_id=request.credential_id,
            action_type=request.action_type,
            details=request.details,
            timestamp=request.timestamp,
            agent_signature=request.agent_signature
        )
        db.add(action_db_item)

    if verdict == "approved" and cred:
        cred.spent_so_far += amount
        cumulative_spend_after = cred.spent_so_far
    else:
        cumulative_spend_after = cred.spent_so_far if cred else 0.0

    # Chain hash lookup
    last_audit = db.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
    prev_hash = last_audit.record_hash if last_audit else "0" * 64
    created_at_time = current_iso_time()

    rec_payload = get_audit_record_payload(
        prev_hash, request.id, request.credential_id, verdict,
        reasons, cumulative_spend_after, created_at_time
    )
    record_hash = hashlib.sha256(canonicalize(rec_payload)).hexdigest()

    audit_entry = AuditRecord(
        prev_hash=prev_hash,
        action_id=request.id,
        credential_id=request.credential_id,
        verdict=verdict,
        reasons=reasons,
        cumulative_spend_after=cumulative_spend_after,
        record_hash=record_hash,
        created_at=created_at_time
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)

    return verdict, reasons, audit_entry


def get_audit_ledger(db: Session) -> Tuple[List[AuditRecord], bool]:
    """Returns all audit records and verifies the SHA-256 hash chain validity."""
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    chain_valid = True

    expected_prev = "0" * 64
    for record in records:
        if record.prev_hash != expected_prev:
            chain_valid = False
            break

        rec_payload = get_audit_record_payload(
            record.prev_hash, record.action_id, record.credential_id,
            record.verdict, record.reasons, record.cumulative_spend_after,
            record.created_at
        )
        computed_hash = hashlib.sha256(canonicalize(rec_payload)).hexdigest()
        if record.record_hash != computed_hash:
            chain_valid = False
            break

        expected_prev = record.record_hash

    return records, chain_valid
