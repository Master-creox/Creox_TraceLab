import base64, hashlib, hmac, json, os, time
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.config import BASE_DIR
from app.database import get_db, utc_now

bearer = HTTPBearer(auto_error=False)

def _secret():
    value=os.getenv("TRACE_LAB_JWT_SECRET", "")
    if len(value)<32:
        raise RuntimeError("Set TRACE_LAB_JWT_SECRET (32+ random characters) in .env")
    return value.encode()

def hash_password(password:str)->str:
    if len(password)<12: raise ValueError("Password must be at least 12 characters")
    salt=os.urandom(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
    return "pbkdf2_sha256$310000$%s$%s"%(base64.urlsafe_b64encode(salt).decode(),base64.urlsafe_b64encode(digest).decode())

def verify_password(password:str,stored:str)->bool:
    try:
        scheme,iterations,salt,digest=stored.split("$")
        if scheme!="pbkdf2_sha256": return False
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),base64.urlsafe_b64decode(salt),int(iterations))
        return hmac.compare_digest(actual,base64.urlsafe_b64decode(digest))
    except Exception: return False

def create_token(username,role):
    header=base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"},separators=(",",":")).encode()).rstrip(b"=")
    payload=base64.urlsafe_b64encode(json.dumps({"sub":username,"role":role,"exp":int(time.time())+1800},separators=(",",":")).encode()).rstrip(b"=")
    body=header+b"."+payload
    sig=base64.urlsafe_b64encode(hmac.new(_secret(),body,hashlib.sha256).digest()).rstrip(b"=")
    return (body+b"."+sig).decode()

def decode_token(token):
    try:
        a,b,c=token.encode().split(b".")
        body=a+b"."+b
        expected=base64.urlsafe_b64encode(hmac.new(_secret(),body,hashlib.sha256).digest()).rstrip(b"=")
        if not hmac.compare_digest(c,expected): raise ValueError()
        payload=json.loads(base64.urlsafe_b64decode(b+b"="*((4-len(b)%4)%4)))
        if payload.get("exp",0)<time.time(): raise ValueError()
        return payload
    except Exception: raise HTTPException(401,"Invalid or expired session",headers={"WWW-Authenticate":"Bearer"})

def current_user(credentials:HTTPAuthorizationCredentials|None=Depends(bearer)):
    if not credentials: raise HTTPException(401,"Please sign in",headers={"WWW-Authenticate":"Bearer"})
    payload=decode_token(credentials.credentials)
    with get_db() as c:
        row=c.execute("SELECT username,role,is_active FROM auth_users WHERE username=?",(payload.get("sub"),)).fetchone()
        if not row or not row["is_active"]: raise HTTPException(401,"Account is inactive or unavailable")
        return dict(row)

def admin_user(user=Depends(current_user)):
    if user["role"]!="admin": raise HTTPException(403,"Administrator role required")
    return user

def record_security_event(actor,action,detail=""):
    import hashlib
    with get_db() as c:
        prev=c.execute("SELECT event_hash FROM security_audit ORDER BY id DESC LIMIT 1").fetchone()
        previous=prev["event_hash"] if prev else "0"*64
        created=utc_now(); payload="|".join([actor,action,detail,created,previous])
        digest=hashlib.sha256(payload.encode()).hexdigest()
        c.execute("INSERT INTO security_audit(actor,action,detail,created_at,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",(actor,action,detail,created,previous,digest))
