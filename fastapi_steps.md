**FastAPI implementation**

**Project structure (recommended)**

# Secure FastAPI Example

This project demonstrates a **production-style FastAPI application** with security, authentication, caching, CI/CD and monitoring baked in.

---

## 📂 Project Structure

```text
myapi/
├─ app/
│  ├─ main.py          # FastAPI app + middleware + routes
│  ├─ db.py            # async DB engine / session
│  ├─ models.py        # SQLAlchemy models
│  ├─ schemas.py       # Pydantic request/response models
│  ├─ crud.py          # DB access functions
│  ├─ auth.py          # JWT, password hashing, auth deps
│  ├─ middleware.py    # logging, rate-limiting, cors, etc.
│  ├─ cache.py         # Redis cache helpers
│  └─ utils.py         # helpers (masking, encryption helpers)
├─ tests/
│  └─ test_users.py    # example pytest test
├─ Dockerfile
└─ .github/workflows/ci.yml  # GitHub Actions pipeline


---

**1) Design & Input Validation (Pydantic + Versioning)**

Goal: validate input early and drop malicious/malformed requests.

**schemas.py**

from pydantic import BaseModel, Field, constr, EmailStr

class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_.-]+$')
    email: EmailStr
    password: constr(min_length=8, max_length=128)

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True

Use constr, EmailStr, and explicit max_length to prevent huge payloads.

Put API under /api/v1/... to support versioning.

**main.py route example:**

from fastapi import FastAPI, Depends
from app.schemas import UserCreate, UserOut

app = FastAPI(title="My API", openapi_prefix="/api/v1")

@app.post("/users", response_model=UserOut)
async def create_user(body: UserCreate):
    # body is already validated by Pydantic
    ...
---

**2) Authentication & Authorization (OAuth2/JWT + RBAC)**

Goal: secure auth, short-lived tokens, refresh tokens and role checks.

**auth.py**

import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/token")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(subject: str, roles: list[str], expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload = {"sub": subject, "roles": roles, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(...)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await db.get_user_by_id(int(user_id))
    if not user:
        raise credentials_exception
    return user

def require_roles(*allowed_roles):
    def role_checker(user=Depends(get_current_user)):
        if not any(r in user.roles for r in allowed_roles):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return role_checker

Use passlib for password hashing, python-jose (or pyjwt) for JWTs.

Store only hashed passwords, never plaintext.

**Token endpoint example**

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from app.auth import create_access_token, verify_password

router = APIRouter()

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(...)):
    user = await db.get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token(str(user.id), roles=user.roles)
    return {"access_token": token, "token_type": "bearer"}

---

**3) HTTPS / TLS & Transport Security**

Goal: always use TLS in production, set security headers.

Dev: you can test local TLS with uvicorn using an SSLContext (self-signed), but production should use a reverse proxy (NGINX, Cloud Load Balancer) with real certs (Let's Encrypt/ACME).

Set HSTS & security headers via middleware.

**main.py (add middleware)**

from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware import Middleware
from starlette.responses import Response

app.add_middleware(HTTPSRedirectMiddleware)  # in production behind TLS
@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

Production: Terminate TLS at load balancer or NGINX. Avoid exposing DB/credentials on HTTP endpoints.

---

**4) Input Size Limits & Sanitization**

Goal: prevent large-payload DoS & XSS injection.

Set client_max_body_size (nginx) or check Content-Length in middleware.

Sanitize HTML content with libraries like bleach before storing or returning.

**middleware.py (payload size)**

from fastapi import Request, HTTPException

MAX_BODY = 1024 * 1024 * 2  # 2 MB

@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Payload too large")
    return await call_next(request)
---

**5) Parameterized DB Access, Pagination & Streaming**

Goal: protect against SQLi, avoid loading millions of rows at once, use keyset pagination, stream large results.

Use SQLAlchemy async (1.4+) or asyncpg. Example with SQLAlchemy async:

**db.py**

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql+asyncpg://user:pass@localhost/db"
engine = create_async_engine(DATABASE_URL, pool_size=20, max_overflow=0)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

**crud.py**

from sqlalchemy import select
from app.models import User

async def get_users_by_name(session: AsyncSession, name: str, limit: int = 100, last_id: int | None = None):
    stmt = select(User.id, User.username, User.email).where(User.name == name)
    if last_id:
        stmt = stmt.where(User.id > last_id)
    stmt = stmt.order_by(User.id).limit(limit)
    result = await session.execute(stmt)
    return result.all()

**Streaming large responses (generator)**

from fastapi.responses import StreamingResponse
import json

async def stream_users(session, name):
    async for row in session.stream(select(User).where(User.name==name)):
        yield json.dumps({"id": row.id, "username": row.username}) + "\n"

@app.get("/users_stream")
async def users_stream(name: str, db=Depends(get_session)):
    return StreamingResponse(stream_users(db, name), media_type="application/x-ndjson")

Use keyset pagination (WHERE id > last_seen) for stable, fast paging.

Always use parameterized queries (SQLAlchemy already does).

---

**6) Caching (Redis) for Hot Data**

Goal: reduce DB load for frequent reads.

**cache.py**

import aioredis, json
redis = aioredis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)

async def get_cached_users(name):
    data = await redis.get(f"users:{name}")
    return json.loads(data) if data else None

async def set_cached_users(name, users, ttl=60):
    await redis.set(f"users:{name}", json.dumps(users), ex=ttl)

**route example**

@app.get("/users")
async def get_users(name: str, db=Depends(get_session)):
    if cached := await cache.get_cached_users(name):
        return cached
    users = await crud.get_users_by_name(db, name)
    await cache.set_cached_users(name, [u._asdict() for u in users], ttl=30)
    return users

Use short TTLs and invalidation on writes. For critical data use cache with versioning or pub/sub invalidation.

---

**7) Rate Limiting & Throttling**

Goal: prevent brute-force and abuse.

Simple Redis counter rate limiter (middleware or dependency):

from starlette.requests import Request
from fastapi import HTTPException
import time

RATE_LIMIT = 100  # requests
WINDOW = 60  # seconds

async def rate_limit(request: Request):
    ip = request.client.host
    key = f"rl:{ip}:{int(time.time() / WINDOW)}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, WINDOW)
    if count > RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")

Attach as dependency in endpoints that need protection, or as global middleware.

For production use robust libraries (e.g., slowapi) or API gateways (Cloudflare, AWS API Gateway) for distributed rate-limiting.

---

**8) Logging, Masking, Monitoring & Tracing**

Goal: observability without exposing sensitive data.

Logging configuration (basic JSON)

import logging, sys, json

logger = logging.getLogger("myapi")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

**Mask sensitive headers & avoid logging full bodies**

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    resp = await call_next(request)
    duration = time.time() - start
    logger.info({
        "method": request.method,
        "path": request.url.path,
        "status": resp.status_code,
        "duration": duration,
        "client": request.client.host
    })
    return resp

**Prometheus metrics**

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

**Tracing**

Add OpenTelemetry for distributed tracing (optional): opentelemetry-instrumentation-fastapi.

Integrate with APM (Datadog, NewRelic, Honeycomb, etc.) in production.

**Centralized logging**

Push logs to ELK / Graylog / Splunk / CloudWatch. Use structured JSON logs.

---

**9) Error Handling & Generic Responses**

Goal: no stack traces leaked, structured errors.

from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled error")
    return JSONResponse({"detail": "Internal server error"}, status_code=500)

Return 401/403/404 with concise messages. Never return SQL errors or stack traces to clients.

---

**10) Vulnerability Scanning & Automated Tests (CI)**

Goal: automate security checks and regression tests.

Unit & integration test example (pytest)
tests/test_sqli.py

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_login_injection():
    res = client.post("/api/v1/token", data={"username":"';--", "password":"x"})
    assert res.status_code == 401

**Security tooling in CI**

pip-audit (detect vulnerable Python deps)

bandit (static security analyzer)

OWASP ZAP or nikto for dynamic scanning

pytest and pytest-cov for unit tests

**Example GitHub Actions steps**

install deps

run pytest

run pip-audit

run bandit

build docker image and scan image (e.g., Trivy)

---

**11) Secrets Management & Rotation**

Goal: avoid environment-variable leaks; rotate secrets.

For dev: ENV variables (use .env carefully).

For prod: use Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault.

Example pattern (pseudocode):

def get_secret(name):
    # in prod, call Vault/Secrets Manager API; in dev, read env var
    return os.getenv(name)

---

**12) Data Encryption (At Rest) & Key Management**

Goal: protect data if DB backup or disk is compromised.

DB-level encryption: enable disk/DB encryption (e.g., AWS RDS encryption).

Field-level encryption for PII:

Use KMS to encrypt/decrypt symmetric keys; use cryptography for AES to encrypt data before saving.

Example (simplified):

from cryptography.fernet import Fernet
from app.utils import get_kms_decrypted_key  # retrieves data key via KMS

KEY = get_kms_decrypted_key("my-data-key")
fernet = Fernet(KEY)

def encrypt_field(plain):
    return fernet.encrypt(plain.encode()).decode()

def decrypt_field(token):
    return fernet.decrypt(token.encode()).decode()

---

**13) Containerization & Deployment Best Practices**

Dockerfile (multi-stage, minimal)

FROM python:3.11-slim AS build
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

FROM python:3.11-slim
RUN adduser --disabled-password appuser
USER appuser
WORKDIR /home/appuser/app
COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

Run container as non-root user.

Scan images with Trivy or similar.

Keep base image small & up to date.

---

**14) WAF, API Gateway & Edge Protection**

Goal: offload common protections and DDoS mitigation.

Use API Gateway (Cloudflare, AWS API Gateway, CloudFront + WAF) to:

Rate-limit at the edge

Block common attack patterns

Terminate TLS

Provide bot management

Keep security rules up-to-date and monitor blocked traffic.

---

**15) Maintenance — Patching & Dependency Management**

Use Dependabot or scheduled CI job to propose updates.

Use pip-audit regularly to surface vulnerable packages.

Patch base OS & language runtime periodically.

---

**16) Example: secure endpoint combining many pieces**

from fastapi import APIRouter, Depends, HTTPException
from app.auth import require_roles
from app.db import AsyncSessionLocal
from app.cache import get_cached_users, set_cached_users

router = APIRouter()

@router.get("/users", response_model=list[UserOut], dependencies=[Depends(rate_limit)])
async def list_users(name: str, last_id: int | None = None, limit: int = 100, db: AsyncSession = Depends(get_session)):
    # cache first
    if cached := await get_cached_users(f"{name}:{last_id}:{limit}"):
        return cached

    users = await crud.get_users_by_name(db, name, limit=limit, last_id=last_id)
    await set_cached_users(f"{name}:{last_id}:{limit}", [u._asdict() for u in users], ttl=30)
    return users

This shows: validation, rate-limiting, DB parameterized query, caching, and pagination.

---

***Quick Production Checklist (summary)***

 Pydantic validation + size limits

 OAuth2/JWT + password hashing + role checks

 HTTPS everywhere (real certs at edge) + security headers

 Parameterized DB queries + keyset pagination + streams

 Redis cache + TTL + invalidation

 Rate limiting (edge + app)

 Structured logging (mask PII) + Prometheus + tracing

 Automated tests + bandit + pip-audit + ZAP in CI

 Image scanning + non-root containers

 Secrets manager + KMS for encryption keys

 WAF / API Gateway / edge DDoS protection

 Regular patching & dependency scans