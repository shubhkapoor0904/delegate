# Implementation Plan - "Delegate" AI Agent Authorization Service

Build a backend service in Python (FastAPI, SQLite, SQLAlchemy, Ed25519 cryptography) that cryptographically verifies whether an AI agent is authorized to perform specific enterprise actions based on signed delegation credentials from human principals.

## User Review Required

> [!IMPORTANT]
> **Key Architecture Decisions**:
> 1. **Ed25519 Cryptography**: All public and private keys are represented as hexadecimal strings (raw 32-byte key representations). Private keys generated server-side during `/principals` and `/agents` creation are returned ONLY in the API response and are never stored in the database.
> 2. **Canonicalization**: The `canonicalize(obj)` function serializes JSON with `sort_keys=True`, `separators=(',', ':')`, UTF-8 encoded. Payload structures omit non-signed/mutable metadata (such as `id`, `signature`, `spent_so_far`, `created_at`).
> 3. **Standalone Verification**: `verify.py` operates completely offline (without dependencies on running servers or DBs), validating the cryptographic proof bundle produced by `demo.py`.

---

## Proposed Changes

### Core Project Structure

#### [NEW] `requirements.txt`
- Dependencies: `fastapi`, `uvicorn`, `sqlalchemy`, `cryptography`, `pydantic`, `pytest`, `httpx`.

#### [NEW] `app/crypto.py`
- `canonicalize(obj) -> bytes`: Deterministic JSON serialization (sorted keys, no spaces, UTF-8).
- `generate_keypair() -> tuple[str, str]`: Generates Ed25519 keypair, returning `(public_key_hex, private_key_hex)`.
- `sign_payload(private_key_hex: str, payload: dict) -> str`: Signs canonicalized payload and returns signature in hex.
- `verify_payload_signature(public_key_hex: str, signature_hex: str, payload: dict) -> bool`: Verifies Ed25519 signature against canonicalized payload.

#### [NEW] `app/models.py`
- SQLAlchemy ORM models:
  - `Principal`: `id` (String PK), `name` (String), `public_key` (String).
  - `Agent`: `id` (String PK), `name` (String), `public_key` (String).
  - `Credential`: `id` (String PK), `issuer_principal_id` (String), `subject_agent_id` (String), `parent_credential_id` (String, nullable), `action_types` (JSON), `categories` (JSON), `max_amount_per_action` (Float), `max_amount_cumulative` (Float), `currency` (String), `valid_from` (DateTime/ISO String), `valid_until` (DateTime/ISO String), `allow_sub_delegation` (Boolean), `status` (String: "active"/"revoked"), `spent_so_far` (Float), `signature` (String), `created_at` (DateTime/ISO String).
  - `ActionRequest`: `id` (String PK), `agent_id` (String), `credential_id` (String), `action_type` (String), `details` (JSON), `timestamp` (DateTime/ISO String), `agent_signature` (String).
  - `AuditRecord`: `id` (Integer PK), `prev_hash` (String), `action_id` (String), `credential_id` (String), `verdict` (String), `reasons` (JSON list), `cumulative_spend_after` (Float), `record_hash` (String), `created_at` (DateTime/ISO String).

#### [NEW] `app/schemas.py`
- Pydantic models for API requests and responses:
  - `PrincipalCreate`, `PrincipalResponse`
  - `AgentCreate`, `AgentResponse`
  - `CredentialCreate`, `CredentialResponse`
  - `ActionRequestCreate`, `ActionResponse`
  - `AuditRecordSchema`, `AuditLedgerResponse`

#### [NEW] `app/services.py`
- **Sub-delegation Scope Checking**: Validates that child credential rules strictly do not exceed parent parameters (categories subset, action_types subset, amounts <= parent, date range within parent, parent `allow_sub_delegation == True` and `status == "active"`).
- **Revocation Cascading**: Walk parent-child links recursively/iteratively and set `status = "revoked"` for all descendant credentials.
- **Action Verification Engine (10 Steps)**:
  1. Replay attack check (`action_id` uniqueness).
  2. Timestamp freshness check (within +/- 5 minutes).
  3. Load credential & verify issuer Ed25519 signature.
  4. Credential active status & valid date window check.
  5. Recursive parent/ancestor credential validation (active status & non-exceeded scope).
  6. Action type & category scope check.
  7. Per-action max amount check (`amount <= max_amount_per_action`).
  8. Cumulative spend check (`spent_so_far + amount <= max_amount_cumulative`).
  9. Agent Ed25519 signature check.
  10. Ledger update: If all pass -> `verdict = "approved"`, update `spent_so_far`. Else -> `verdict = "rejected"`. Write audit record with hash chain (`prev_hash` + `record_hash`).
- **Audit Ledger Hash Verification**: Re-computes chain hashes to confirm `chain_valid`.

#### [NEW] `app/main.py`
- FastAPI application setup, database migration/initialization, mounting static UI files, exposing endpoints:
  - `POST /principals`
  - `POST /agents`
  - `POST /credentials`
  - `POST /credentials/{id}/revoke`
  - `GET /credentials/{id}`
  - `POST /actions`
  - `GET /audit`

#### [NEW] `static/index.html`
- Clean, functional, anti-cliché enterprise dashboard UI:
  - **UI Directives (Strict Anti-Vibe-Coding Rules)**:
    - No harsh gradients, radial orbs, liquid glass, drop shadows, or neon colors.
    - No purple-and-black themes, rainbow accents, or basic pastel palettes.
    - No Lucide icons, sparkle icons, emojis, or animated arrows.
    - No bento grids, 3-card rows, terminal window gimmicks, or fake testimonials.
    - Clean, subtle slate/neutral enterprise design with sharp crisp lines and clear data tables for principals, agents, credentials, actions, and audit ledgers.

---

### Standalone Verifier & CLI Scripted Demo

#### [NEW] `verify.py`
- Standalone verification script (`python verify.py bundle.json`) that checks a Verifiable Presentation bundle without contacting server or DB. Validates all delegation chain signatures and scopes offline.

#### [NEW] `demo.py`
- CLI demonstration executing steps 1-10 sequentially:
  1. Register principal "priya" and agent "procurement-intake-agent-v1".
  2. Issue root credential (category=software, max_per_action=5000, max_cumulative=20000, 90 days valid, sub_delegation=true).
  3. Submit action: $3,200 SaaS renewal → expect `approved`.
  4. Submit action: $6,000 → expect `rejected` (exceeds max_amount_per_action).
  5. Revoke the credential.
  6. Resubmit $3,200 action with new action_id → expect `rejected` (credential not active).
  7. Print audit ledger and `chain_valid`.
  8. Export action bundle to `bundle.json`.
  9. Run `python verify.py bundle.json` via subprocess and print independent output.

---

### Test Suite

#### [NEW] `tests/test_delegate.py`
- Pytest tests covering all required scenario checks:
  1. Root credential issuance & in-scope action -> `approved`
  2. Exceeding `max_amount_per_action` -> `rejected`
  3. Exceeding `max_amount_cumulative` across multiple actions -> `rejected` on tipping action
  4. Action with revoked credential -> `rejected`
  5. Revoking parent cascades to child credential -> child action `rejected`
  6. Action replay (`action_id` reuse) -> `rejected`
  7. Signature tampering (modifying amount after agent signing) -> signature check failure
  8. Over-broad sub-delegation scope -> `/credentials` creation rejected

---

## Verification Plan

### Automated Tests
- Run `pytest` to verify all test cases in `tests/test_delegate.py`.

### Scripted Demo & Verification
- Execute `python demo.py` to confirm end-to-end execution, audit log creation, hash chaining, and bundle verification via `verify.py`.

### UI Manual Verification
- Start `uvicorn app.main:app` and access `http://127.0.0.1:8000` in browser to test credential issuance and action request UI manually.
