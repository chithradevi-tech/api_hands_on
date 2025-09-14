**1️⃣ Why Database Optimization Matters**

Most REST APIs are I/O bound — meaning waiting on the database is the slowest step.
Optimizing your DB access typically yields the biggest performance gains (5×–10×).

---

**2️⃣ Core Principles**

| Principle                   | Explanation                                   |
| --------------------------- | --------------------------------------------- |
| **Minimize round-trips**    | Fewer queries → less latency.                 |
| **Use proper indexing**     | Index on fields used in WHERE/JOIN/ORDER.     |
| **Cache hot data**          | Store in Redis/in-memory to avoid DB.         |
| **Async drivers**           | Non-blocking IO frees worker threads.         |
| **Connection pooling**      | Reuse DB connections instead of reconnecting. |
| **Pagination & projection** | Return only what you need.                    |
| **Batch writes/reads**      | Insert many rows at once.                     |
| **Avoid N+1 queries**       | Prefetch related data.                        |


---

**3️⃣ Database Choices & Architecture**

PostgreSQL/MySQL: relational, good for transactions.

NoSQL (MongoDB, Redis): good for caching, large-scale reads.

Read replicas: direct heavy-read endpoints to replicas.

Sharding/Partitioning: large datasets spread across servers.

---

**4️⃣ Implementing in Python FastAPI**

4.1 Connection Pooling with Async SQLAlchemy

# app/db.py

```text

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql+asyncpg://user:password@localhost/mydb"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=10,         # initial pool size
    max_overflow=20,      # extra connections during spikes
)
SessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
        
```

Why it’s fast:

Uses asyncpg driver (fast).

Keeps open connections in a pool.

---

**4.2 Async Queries + Parameterization**

# app/crud.py

```text

from sqlalchemy import select
from .models import User

async def get_user_by_email(db, email: str):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalars().first()
```

Why it’s fast:

No SQL injection risk (parameters).

Efficient compiled SQL.

---

**4.3 Indexing**

```text

In models.py:

from sqlalchemy import Column, Integer, String, Index
from app.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, index=True)  # built-in index

Index("ix_users_email", User.email)

```
Why it’s fast:

Index on email speeds lookups 10×–100×.

---

**4.4 Pagination & Projection**

```text

@app.get("/users")
async def list_users(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(User.id, User.email).offset(skip).limit(limit))
    return result.all()
```

Why it’s fast:

Doesn’t load entire table.

Returns only columns needed.

---

**4.5 Caching with Redis**

# app/cache.py

```text

import aioredis
import json

redis = aioredis.from_url("redis://localhost")

async def cache_get(key):
    val = await redis.get(key)
    return json.loads(val) if val else None

async def cache_set(key, value, ttl=60):
    await redis.set(key, json.dumps(value), ex=ttl)
```

Usage:

```text

@app.get("/users/{user_id}")
async def get_user(user_id: int, db: AsyncSession = Depends(get_session)):
    cached = await cache_get(f"user:{user_id}")
    if cached:
        return cached
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user:
        await cache_set(f"user:{user_id}", {"id": user.id, "email": user.email})
    return user
```

Why it’s fast:

Hot data served in microseconds from Redis.

---

**4.6 Bulk Operations**

Instead of inserting in a loop:

# slow
```text
for row in rows:
    db.add(User(**row))
await db.commit()
```

Do this:

# fast
```text
db.add_all([User(**row) for row in rows])
await db.commit()
```

Or:
```text
await db.execute(User.__table__.insert(), rows)  # bulk insert
```
---

**4.7 Avoiding N+1 Queries**

Use selectinload to fetch related objects in one go:

```text

from sqlalchemy.orm import selectinload

result = await db.execute(
    select(User).options(selectinload(User.posts))
)
users = result.scalars().all()
```

---

**4.8 Read Replicas**

Set up a replica DB for read-heavy endpoints.

Create two SQLAlchemy engines: one for write, one for read.

Route GET endpoints to the read engine.

---

**5️⃣ Monitoring and Profiling**

Log slow queries: SQLALCHEMY_ECHO=True or Postgres log_min_duration_statement.

Use APM (Datadog, New Relic, OpenTelemetry) to see query times.

Add Prometheus metrics for DB query count/latency.

---

**6️⃣ Infrastructure Tips**

Deploy DB close to your app server (low latency).

Use proper instance sizes and SSD storage.

Increase DB max_connections to match your pool size.

Turn on connection keepalive.

---

**7️⃣ Putting It All Together**

| Layer                 | Gain                            |
| --------------------- | ------------------------------- |
| Async DB driver       | 2–3× faster than sync           |
| Connection pool       | 2× less latency on new requests |
| Caching hot endpoints | 10× speedup on repeated calls   |
| Proper indexing       | 5–100× on certain queries       |
| Pagination            | Linear memory savings           |


---

**✅ Summary**

Use async SQLAlchemy + connection pools.

Add indexes and paginate.

Cache hot data with Redis.

Use bulk inserts and avoid N+1 queries.

Consider read replicas for scale.

Monitor everything.