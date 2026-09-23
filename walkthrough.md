# Walkthrough - Delegate AI Agent Authorization Service

The **Delegate** service has been fully built to cryptographically verify AI agent authorization credentials using Ed25519 signatures, recursive sub-delegation scope checking, revocation cascading, and SHA-256 audit ledger hash chaining.

## Key Implemented Features

1. **Deterministic Canonicalization (`app/crypto.py`)**:
   - `canonicalize(obj)` formats all JSON objects with sorted keys, zero whitespace (`separators=(',', ':')`), UTF-8 encoded before signing or verifying signatures.
   - Keypair generation (`generate_keypair()`) generates Ed25519 keypairs. Private keys are returned server-side in API responses for demo convenience and are **never** stored in the database.

2. **Database Models & ORM (`app/models.py`)**:
   - SQLite models via SQLAlchemy: `Principal`, `Agent`, `Credential`, `ActionRequest`, and `AuditRecord`.

3. **Core Verification Engine & Service Layer (`app/services.py`)**:
   - **Sub-delegation Scope Validation**: Enforces strict subset rules for categories, action_types, amounts, date windows, and active sub-delegation permissions on parent credentials.
   - **Revocation Cascading**: Iteratively/recursively revokes all child credentials when a parent credential is revoked.
   - **10-Step Verification Engine**:
     1. Replay protection (`action_id` uniqueness check)
     2. Timestamp freshness window (within +/- 5 minutes)
     3. Issuer Ed25519 signature verification on credential
     4. Active status & validity date window check
     5. Recursive ancestor credential validation (defense-in-depth)
     6. Action type & category scope matching
     7. Per-action amount limit check (`max_amount_per_action`)
     8. Cumulative amount limit check (`spent_so_far + amount <= max_amount_cumulative`)
     9. Agent Ed25519 signature verification on action request
     10. Ledger entry creation with SHA-256 hash chaining (`prev_hash` + `record_hash`)
   - **Audit Ledger Hash Chain Verification (`GET /audit`)**: Dynamically verifies the validity of the SHA-256 hash chain links (`chain_valid`).

4. **FastAPI Application (`app/main.py`)**:
   - Exposes RESTful endpoints:
     - `POST /principals`
     - `POST /agents`
     - `POST /credentials`
     - `POST /credentials/{id}/revoke`
     - `GET /credentials/{id}`
     - `POST /actions`
     - `GET /audit`
     - Static web UI serving at `/`

5. **Pytest Test Suite (`tests/test_delegate.py`)**:
   - Covers all required edge cases and scenarios:
     1. In-scope action request approval
     2. Exceeding `max_amount_per_action` rejection
     3. Exceeding `max_amount_cumulative` rejection
     4. Revoked credential rejection
     5. Parent revocation cascading to child credential
     6. Replay attack rejection
     7. Signature tampering rejection
     8. Over-broad sub-delegation scope creation rejection (400 HTTP status)

6. **CLI Demo Walkthrough (`demo.py`)**:
   - Executes steps 1–10 automatically, generates `bundle.json`, and verifies the proof offline.

7. **Standalone Offline Verifier (`verify.py`)**:
   - Command: `python verify.py bundle.json`
   - Operates completely offline without contacting server or database.

8. **Enterprise Web UI (`static/index.html`)**:
   - Anti-vibe-coded, utilitarian dashboard adhering strictly to your design directives (no harsh gradients, no purple-and-black theme, no Lucide/sparkle icons, no radial orbs, no bento grids, no fake marketing jargon).

---

## File Summary

| File Path | Description |
| :--- | :--- |
| [requirements.txt](file:///d:/delegate/requirements.txt) | Python dependencies (`fastapi`, `uvicorn`, `sqlalchemy`, `cryptography`, `pytest`, `httpx`). |
| [app/crypto.py](file:///d:/delegate/app/crypto.py) | Canonicalization helper and Ed25519 signing/verifying functions. |
| [app/models.py](file:///d:/delegate/app/models.py) | SQLAlchemy database models (`Principal`, `Agent`, `Credential`, `ActionRequest`, `AuditRecord`). |
| [app/schemas.py](file:///d:/delegate/app/schemas.py) | Pydantic request and response schemas. |
| [app/services.py](file:///d:/delegate/app/services.py) | Business logic, scope validation, revocation cascading, 10-step Action Engine, and audit ledger chaining. |
| [app/main.py](file:///d:/delegate/app/main.py) | FastAPI app entry point and API route definitions. |
| [tests/test_delegate.py](file:///d:/delegate/tests/test_delegate.py) | Pytest test suite covering all 8 mandatory scenario test cases. |
| [verify.py](file:///d:/delegate/verify.py) | Offline standalone presentation verifier script (`python verify.py bundle.json`). |
| [demo.py](file:///d:/delegate/demo.py) | Scripted CLI demo walking through steps 1–9. |
| [static/index.html](file:///d:/delegate/static/index.html) | Clean, functional enterprise UI for manually testing credentials and actions. |

---

## How to Run & Test

### 1. Run the FastAPI Server & Web UI
```bash
uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000` in your browser to access the clean enterprise dashboard.

### 2. Run the Scripted CLI Demo
```bash
python demo.py
```

### 3. Run Standalone Bundle Verification
```bash
python verify.py bundle.json
```

### 4. Run Pytest Suite
```bash
pytest -v
```
