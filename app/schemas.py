from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class PrincipalCreate(BaseModel):
    id: Optional[str] = None
    name: str


class PrincipalResponse(BaseModel):
    id: str
    name: str
    public_key: str


class AgentCreate(BaseModel):
    id: Optional[str] = None
    name: str


class AgentResponse(BaseModel):
    id: str
    name: str
    public_key: str


class CredentialCreate(BaseModel):
    id: Optional[str] = None
    issuer_principal_id: str
    subject_agent_id: str
    parent_credential_id: Optional[str] = None
    action_types: List[str]
    categories: List[str]
    max_amount_per_action: float
    max_amount_cumulative: float
    currency: str = "USD"
    valid_from: str
    valid_until: str
    allow_sub_delegation: bool = False
    issuer_private_key: Optional[str] = None


class CredentialResponse(BaseModel):
    id: str
    issuer_principal_id: str
    subject_agent_id: str
    parent_credential_id: Optional[str] = None
    action_types: List[str]
    categories: List[str]
    max_amount_per_action: float
    max_amount_cumulative: float
    currency: str
    valid_from: str
    valid_until: str
    allow_sub_delegation: bool
    status: str
    spent_so_far: float
    signature: str
    created_at: str

    class Config:
        from_attributes = True


class ActionRequestCreate(BaseModel):
    id: str
    agent_id: str
    credential_id: str
    action_type: str
    details: Dict[str, Any]
    timestamp: str
    agent_signature: Optional[str] = None


class AuditRecordSchema(BaseModel):
    id: int
    prev_hash: str
    action_id: str
    credential_id: str
    verdict: str
    reasons: List[str]
    cumulative_spend_after: float
    record_hash: str
    created_at: str

    class Config:
        from_attributes = True


class ActionResponse(BaseModel):
    verdict: str
    reasons: List[str]
    audit_record: AuditRecordSchema


class AuditLedgerResponse(BaseModel):
    records: List[AuditRecordSchema]
    chain_valid: bool
