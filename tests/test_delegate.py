import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app, get_db
from app.models import Base
from app.crypto import sign_payload, get_action_request_payload

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def test_1_root_credential_in_scope_approved():
    # 1. Register principal and agent
    p_resp = client.post("/principals", json={"name": "priya"})
    assert p_resp.status_code == 200
    p_data = p_resp.json()
    principal_id = p_data["id"]
    principal_priv_key = p_data["private_key"]

    a_resp = client.post("/agents", json={"name": "procurement-agent"})
    assert a_resp.status_code == 200
    a_data = a_resp.json()
    agent_id = a_data["id"]
    agent_priv_key = a_data["private_key"]

    # 2. Issue root credential
    now = datetime.now(timezone.utc)
    valid_from = (now - timedelta(minutes=1)).isoformat()
    valid_until = (now + timedelta(days=90)).isoformat()

    c_resp = client.post("/credentials", json={
        "issuer_principal_id": principal_id,
        "subject_agent_id": agent_id,
        "action_types": ["purchase", "renew"],
        "categories": ["software", "hardware"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "allow_sub_delegation": True,
        "issuer_private_key": principal_priv_key
    })
    assert c_resp.status_code == 200
    cred_id = c_resp.json()["id"]

    # 3. Submit action request within scope ($3,200 software renewal)
    action_id = "action-001"
    timestamp = datetime.now(timezone.utc).isoformat()
    details = {"category": "software", "amount": 3200.0, "vendor": "SaaS Vendor"}

    payload_to_sign = {
        "id": action_id,
        "agent_id": agent_id,
        "credential_id": cred_id,
        "action_type": "renew",
        "details": details,
        "timestamp": timestamp
    }
    agent_signature = sign_payload(agent_priv_key, payload_to_sign)

    act_resp = client.post("/actions", json={
        "id": action_id,
        "agent_id": agent_id,
        "credential_id": cred_id,
        "action_type": "renew",
        "details": details,
        "timestamp": timestamp,
        "agent_signature": agent_signature
    })
    assert act_resp.status_code == 200
    act_data = act_resp.json()
    assert act_data["verdict"] == "approved"
    assert act_data["reasons"] == []


def test_2_exceed_max_amount_per_action_rejected():
    # Setup
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    c_data = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Submit action exceeding max_amount_per_action ($6,000 > $5,000)
    action_id = "action-exceed-per-action"
    timestamp = datetime.now(timezone.utc).isoformat()
    details = {"category": "software", "amount": 6000.0}

    payload = {
        "id": action_id,
        "agent_id": a_data["id"],
        "credential_id": c_data["id"],
        "action_type": "purchase",
        "details": details,
        "timestamp": timestamp
    }
    sig = sign_payload(a_data["private_key"], payload)

    resp = client.post("/actions", json={
        "id": action_id,
        "agent_id": a_data["id"],
        "credential_id": c_data["id"],
        "action_type": "purchase",
        "details": details,
        "timestamp": timestamp,
        "agent_signature": sig
    }).json()

    assert resp["verdict"] == "rejected"
    assert "exceeds max_amount_per_action" in resp["reasons"]


def test_3_exceed_cumulative_cap_rejected():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    c_data = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 7000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Action 1: $4,000 (Approved)
    t1 = datetime.now(timezone.utc).isoformat()
    d1 = {"category": "software", "amount": 4000.0}
    sig1 = sign_payload(a_data["private_key"], {"id": "act-1", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d1, "timestamp": t1})
    r1 = client.post("/actions", json={"id": "act-1", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d1, "timestamp": t1, "agent_signature": sig1}).json()
    assert r1["verdict"] == "approved"

    # Action 2: $4,000 ($4,000 + $4,000 = $8,000 > $7,000 cap) -> Rejected
    t2 = datetime.now(timezone.utc).isoformat()
    d2 = {"category": "software", "amount": 4000.0}
    sig2 = sign_payload(a_data["private_key"], {"id": "act-2", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d2, "timestamp": t2})
    r2 = client.post("/actions", json={"id": "act-2", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d2, "timestamp": t2, "agent_signature": sig2}).json()
    assert r2["verdict"] == "rejected"
    assert "exceeds max_amount_cumulative" in r2["reasons"]


def test_4_action_with_revoked_credential_rejected():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    c_data = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Revoke credential
    client.post(f"/credentials/{c_data['id']}/revoke")

    # Try submitting action
    t = datetime.now(timezone.utc).isoformat()
    d = {"category": "software", "amount": 1000.0}
    sig = sign_payload(a_data["private_key"], {"id": "act-rev", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d, "timestamp": t})
    r = client.post("/actions", json={"id": "act-rev", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d, "timestamp": t, "agent_signature": sig}).json()
    assert r["verdict"] == "rejected"
    assert "credential not active" in r["reasons"]


def test_5_parent_revocation_cascades_to_child():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    # Root credential
    root_c = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Child credential
    child_c = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "parent_credential_id": root_c["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 2000.0,
        "max_amount_cumulative": 5000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "allow_sub_delegation": False,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Revoke Root
    client.post(f"/credentials/{root_c['id']}/revoke")

    # Check child status endpoint
    get_child = client.get(f"/credentials/{child_c['id']}").json()
    assert get_child["status"] == "revoked"

    # Action on child should be rejected
    t = datetime.now(timezone.utc).isoformat()
    d = {"category": "software", "amount": 1000.0}
    sig = sign_payload(a_data["private_key"], {"id": "act-child", "agent_id": a_data["id"], "credential_id": child_c["id"], "action_type": "purchase", "details": d, "timestamp": t})
    r = client.post("/actions", json={"id": "act-child", "agent_id": a_data["id"], "credential_id": child_c["id"], "action_type": "purchase", "details": d, "timestamp": t, "agent_signature": sig}).json()
    assert r["verdict"] == "rejected"


def test_6_replay_exact_action_id_rejected():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    c_data = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Submit action 1
    t = datetime.now(timezone.utc).isoformat()
    d = {"category": "software", "amount": 1000.0}
    sig = sign_payload(a_data["private_key"], {"id": "action-replay-id", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d, "timestamp": t})

    r1 = client.post("/actions", json={"id": "action-replay-id", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d, "timestamp": t, "agent_signature": sig}).json()
    assert r1["verdict"] == "approved"

    # Resubmit identical action ID
    r2 = client.post("/actions", json={"id": "action-replay-id", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": d, "timestamp": t, "agent_signature": sig}).json()
    assert r2["verdict"] == "rejected"
    assert "Action ID already processed" in r2["reasons"][0]


def test_7_tamper_amount_after_signing_invalidates_signature():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    c_data = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Agent signs for $1,000
    t = datetime.now(timezone.utc).isoformat()
    original_details = {"category": "software", "amount": 1000.0}
    sig = sign_payload(a_data["private_key"], {"id": "tamper-act", "agent_id": a_data["id"], "credential_id": c_data["id"], "action_type": "purchase", "details": original_details, "timestamp": t})

    # Tamper with payload: change amount to $2,000 while keeping original signature
    tampered_details = {"category": "software", "amount": 2000.0}
    r = client.post("/actions", json={
        "id": "tamper-act",
        "agent_id": a_data["id"],
        "credential_id": c_data["id"],
        "action_type": "purchase",
        "details": tampered_details,
        "timestamp": t,
        "agent_signature": sig
    }).json()

    assert r["verdict"] == "rejected"
    assert "Invalid agent signature" in r["reasons"][0]


def test_8_overbroad_subdelegation_rejected_at_issuance():
    p_data = client.post("/principals", json={"name": "priya"}).json()
    a_data = client.post("/agents", json={"name": "agent"}).json()

    now = datetime.now(timezone.utc)
    # Parent allows software category up to $5,000
    root_c = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "action_types": ["purchase"],
        "categories": ["software"],
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": True,
        "issuer_private_key": p_data["private_key"]
    }).json()

    # Attempt child with broader category ["software", "hardware"] or higher amount $10,000
    sub_resp = client.post("/credentials", json={
        "issuer_principal_id": p_data["id"],
        "subject_agent_id": a_data["id"],
        "parent_credential_id": root_c["id"],
        "action_types": ["purchase"],
        "categories": ["software", "hardware"], # Exceeds parent categories!
        "max_amount_per_action": 5000.0,
        "max_amount_cumulative": 20000.0,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=90)).isoformat(),
        "allow_sub_delegation": False,
        "issuer_private_key": p_data["private_key"]
    })

    assert sub_resp.status_code == 400
    assert "exceed parent categories" in sub_resp.json()["detail"]
