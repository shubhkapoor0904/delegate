import uuid
from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.models import Base, engine, SessionLocal, Principal, Agent, Credential, init_db
from app.crypto import generate_keypair, sign_payload
from app.schemas import (
    PrincipalCreate, PrincipalResponse,
    AgentCreate, AgentResponse,
    CredentialCreate, CredentialResponse,
    ActionRequestCreate, ActionResponse,
    AuditLedgerResponse, AuditRecordSchema
)
from app.services import (
    IN_MEMORY_KEY_STORE, get_credential_payload, validate_sub_delegation,
    revoke_credential_cascade, verify_action_request, get_audit_ledger
)

init_db()

app = FastAPI(title="Delegate - AI Agent Authorization Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/principals", response_model=PrincipalResponse)
def register_principal(payload: PrincipalCreate, db: Session = Depends(get_db)):
    pub_key, priv_key = generate_keypair()
    principal_id = payload.id if payload.id else f"principal-{uuid.uuid4().hex[:8]}"

    existing = db.query(Principal).filter(Principal.id == principal_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Principal ID already exists")

    principal = Principal(id=principal_id, name=payload.name, public_key=pub_key)
    db.add(principal)
    db.commit()

    # Save private key ONLY in server in-memory store, never return to frontend
    IN_MEMORY_KEY_STORE[principal.id] = priv_key

    return PrincipalResponse(
        id=principal.id,
        name=principal.name,
        public_key=pub_key
    )


@app.get("/principals", response_model=List[PrincipalResponse])
def list_principals(db: Session = Depends(get_db)):
    return db.query(Principal).all()


@app.post("/agents", response_model=AgentResponse)
def register_agent(payload: AgentCreate, db: Session = Depends(get_db)):
    pub_key, priv_key = generate_keypair()
    agent_id = payload.id if payload.id else f"agent-{uuid.uuid4().hex[:8]}"

    existing = db.query(Agent).filter(Agent.id == agent_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Agent ID already exists")

    agent = Agent(id=agent_id, name=payload.name, public_key=pub_key)
    db.add(agent)
    db.commit()

    # Save private key ONLY in server in-memory store, never return to frontend
    IN_MEMORY_KEY_STORE[agent.id] = priv_key

    return AgentResponse(
        id=agent.id,
        name=agent.name,
        public_key=pub_key
    )


@app.get("/agents", response_model=List[AgentResponse])
def list_agents(db: Session = Depends(get_db)):
    return db.query(Agent).all()


@app.post("/credentials", response_model=CredentialResponse)
def issue_credential(req: CredentialCreate, db: Session = Depends(get_db)):
    # Validate issuer exists
    issuer = db.query(Principal).filter(Principal.id == req.issuer_principal_id).first()
    if not issuer:
        raise HTTPException(status_code=404, detail="Issuer principal not found")

    # Validate subject agent exists
    subject = db.query(Agent).filter(Agent.id == req.subject_agent_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Subject agent not found")

    # If parent_credential_id is given, validate sub-delegation scope subset
    if req.parent_credential_id:
        parent_cred = db.query(Credential).filter(Credential.id == req.parent_credential_id).first()
        if not parent_cred:
            raise HTTPException(status_code=404, detail="Parent credential not found")
        validate_sub_delegation(req, parent_cred)

    cred_id = req.id if req.id else f"cred-{uuid.uuid4().hex[:8]}"

    # Determine private key for signing
    issuer_priv = req.issuer_private_key or IN_MEMORY_KEY_STORE.get(req.issuer_principal_id)
    if not issuer_priv:
        raise HTTPException(
            status_code=400,
            detail="Issuer private key not provided and not found in server key store"
        )

    # Canonicalize and sign
    sig_payload = get_credential_payload(
        cred_id, req.issuer_principal_id, req.subject_agent_id,
        req.parent_credential_id, req.action_types, req.categories,
        req.max_amount_per_action, req.max_amount_cumulative, req.currency,
        req.valid_from, req.valid_until, req.allow_sub_delegation
    )

    try:
        signature = sign_payload(issuer_priv, sig_payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to sign credential: {e}")

    credential = Credential(
        id=cred_id,
        issuer_principal_id=req.issuer_principal_id,
        subject_agent_id=req.subject_agent_id,
        parent_credential_id=req.parent_credential_id,
        action_types=req.action_types,
        categories=req.categories,
        max_amount_per_action=req.max_amount_per_action,
        max_amount_cumulative=req.max_amount_cumulative,
        currency=req.currency,
        valid_from=req.valid_from,
        valid_until=req.valid_until,
        allow_sub_delegation=req.allow_sub_delegation,
        status="active",
        spent_so_far=0.0,
        signature=signature
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)

    return credential


@app.get("/credentials", response_model=List[CredentialResponse])
def list_credentials(db: Session = Depends(get_db)):
    return db.query(Credential).all()


@app.post("/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: str, db: Session = Depends(get_db)):
    cascaded_count = revoke_credential_cascade(db, credential_id)
    return {
        "status": "revoked",
        "credential_id": credential_id,
        "revoked_count": cascaded_count
    }


@app.get("/credentials/{credential_id}", response_model=CredentialResponse)
def get_credential(credential_id: str, db: Session = Depends(get_db)):
    cred = db.query(Credential).filter(Credential.id == credential_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    return cred


@app.post("/actions", response_model=ActionResponse)
def submit_action(req: ActionRequestCreate, db: Session = Depends(get_db)):
    verdict, reasons, audit_record = verify_action_request(db, req)
    return ActionResponse(
        verdict=verdict,
        reasons=reasons,
        audit_record=AuditRecordSchema.model_validate(audit_record)
    )


@app.get("/audit", response_model=AuditLedgerResponse)
def get_audit(db: Session = Depends(get_db)):
    records, chain_valid = get_audit_ledger(db)
    return AuditLedgerResponse(
        records=[AuditRecordSchema.model_validate(r) for r in records],
        chain_valid=chain_valid
    )


# Mount static directory for Web UI
app.mount("/", StaticFiles(directory="static", html=True), name="static")
