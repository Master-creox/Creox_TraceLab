import pytest
from app.security import hash_password, verify_password, create_token, decode_token

def test_password_hash_and_verify():
    encoded=hash_password("A-strong-test-password-2026!")
    assert encoded != "A-strong-test-password-2026!"
    assert verify_password("A-strong-test-password-2026!",encoded)
    assert not verify_password("incorrect-password",encoded)

def test_password_minimum_length():
    with pytest.raises(ValueError): hash_password("short")

def test_token_signature_and_payload(monkeypatch):
    monkeypatch.setenv("TRACE_LAB_JWT_SECRET","unit-test-secret-that-is-longer-than-32-characters")
    token=create_token("analyst1","analyst")
    payload=decode_token(token)
    assert payload["sub"]=="analyst1" and payload["role"]=="analyst"
    first,second,signature=token.split(".")
    tampered=first+"."+second+"."+("A" if signature[0]!="A" else "B")+signature[1:]
    with pytest.raises(Exception): decode_token(tampered)
