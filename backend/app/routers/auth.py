from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone

# Security Configurations
SECRET_KEY = "sentinel_ai_super_secret_hackathon_key"
ALGORITHM = "HS256"

router = APIRouter(prefix="/api/auth", tags=["Auth"])
security_scheme = HTTPBearer()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login_admin(req: LoginRequest):
    # Hackathon Shortcut: Hardcoded admin credentials
    if req.username == "admin" and req.password == "admin123":
        payload = {
            "sub": req.username,
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=4) # Token valid for 4 hours
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    
    raise HTTPException(status_code=401, detail="Invalid admin credentials")

# Dependency to protect routes
def verify_admin(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not authorized as admin")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")