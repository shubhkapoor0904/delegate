from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Float, Boolean, Integer, JSON, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./delegate.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def current_iso_time() -> str:
    """Returns current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class Principal(Base):
    __tablename__ = "principals"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    public_key = Column(String, nullable=False)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    public_key = Column(String, nullable=False)


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(String, primary_key=True, index=True)
    issuer_principal_id = Column(String, ForeignKey("principals.id"), nullable=False)
    subject_agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    parent_credential_id = Column(String, ForeignKey("credentials.id"), nullable=True)

    action_types = Column(JSON, nullable=False)  # list of strings
    categories = Column(JSON, nullable=False)    # list of strings
    max_amount_per_action = Column(Float, nullable=False)
    max_amount_cumulative = Column(Float, nullable=False)
    currency = Column(String, nullable=False, default="USD")

    valid_from = Column(String, nullable=False)   # ISO format string
    valid_until = Column(String, nullable=False)  # ISO format string
    allow_sub_delegation = Column(Boolean, nullable=False, default=False)
    status = Column(String, nullable=False, default="active")  # active/revoked
    spent_so_far = Column(Float, nullable=False, default=0.0)

    signature = Column(String, nullable=False)
    created_at = Column(String, nullable=False, default=current_iso_time)

    # Relationships
    issuer = relationship("Principal", foreign_keys=[issuer_principal_id])
    subject = relationship("Agent", foreign_keys=[subject_agent_id])
    parent = relationship("Credential", remote_side=[id])


class ActionRequest(Base):
    __tablename__ = "action_requests"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    credential_id = Column(String, ForeignKey("credentials.id"), nullable=False)
    action_type = Column(String, nullable=False)
    details = Column(JSON, nullable=False)  # dict containing amount, category, vendor, etc.
    timestamp = Column(String, nullable=False)  # ISO format string
    agent_signature = Column(String, nullable=False)

    agent = relationship("Agent")
    credential = relationship("Credential")


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    prev_hash = Column(String, nullable=False)
    action_id = Column(String, nullable=False)
    credential_id = Column(String, nullable=False)
    verdict = Column(String, nullable=False)  # approved / rejected / escalated
    reasons = Column(JSON, nullable=False)    # list of string error messages
    cumulative_spend_after = Column(Float, nullable=False)
    record_hash = Column(String, nullable=False)
    created_at = Column(String, nullable=False, default=current_iso_time)


def init_db():
    Base.metadata.create_all(bind=engine)
