import os
import json
import hmac
import hashlib
from urllib.parse import parse_qsl
from typing import Any, Dict, Optional

import asyncpg
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
WEBAPP_ORIGINS = os.getenv("WEBAPP_ORIGINS", "").strip()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN env is required")
if not ADMIN_API_TOKEN:
    raise RuntimeError("ADMIN_API_TOKEN env is required")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env is required")

app = FastAPI(title="Shetka API")

origins = [o.strip() for o in WEBAPP_ORIGINS.split(",") if o.strip()] if WEBAPP_ORIGINS else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pool: Optional[asyncpg.Pool] = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
  tg_id BIGINT PRIMARY KEY,
  first_name TEXT,
  last_name TEXT,
  username TEXT,
  phone TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  public_no TEXT UNIQUE NOT NULL,
  owner_tg_id BIGINT,
  owner_phone TEXT,
  item TEXT NOT NULL,
  services_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  price INTEGER,
  comment TEXT,
  is_closed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_orders_owner_tg ON orders(owner_tg_id);
CREATE INDEX IF NOT EXISTS idx_orders_public_no ON orders(public_no);
"""

def verify_init_data(init_data: str) -> Dict[str, Any]:
    if not init_data:
        raise HTTPException(401, "Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    recv_hash = pairs.get("hash")
    if not recv_hash:
        raise HTTPException(401, "Missing hash")

    pairs.pop("hash", None)
    data_check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs.keys()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc_hash = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()

    if calc_hash != recv_hash:
        raise HTTPException(401, "Bad signature")

    user_raw = pairs.get("user")
    if not user_raw:
        raise HTTPException(401, "Missing user")
    try:
        return json.loads(user_raw)
    except Exception:
        raise HTTPException(401, "Bad user json")

@app.on_event("startup")
async def startup():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)

def require_pool() -> asyncpg.Pool:
    if not pool:
        raise RuntimeError("DB not ready")
    return pool

def require_admin(token: str):
    if token != ADMIN_API_TOKEN:
        raise HTTPException(401, "Bad admin token")

@app.get("/api/me/orders")
async def me_orders(x_telegram_initdata: str = Header(default="")):
    user = verify_init_data(x_telegram_initdata)
    tg_id = int(user["id"])

    p = require_pool()
    async with p.acquire() as conn:
        rows = await conn.fetch(
            "SELECT public_no,item,services_json,status,price,comment,created_at,updated_at FROM orders WHERE owner_tg_id=$1 ORDER BY created_at DESC",
            tg_id
        )

    orders = []
    for r in rows:
        services = json.loads(r["services_json"] or "[]")
        orders.append({
            "public_no": r["public_no"],
            "item": r["item"],
            "services": services,
            "status": r["status"],
            "price": r["price"],
            "comment": r["comment"],
            "created_at": r["created_at"].isoformat(),
            "updated_at": r["updated_at"].isoformat(),
        })

    return {"ok": True, "orders": orders}

@app.post("/api/admin/order/upsert")
async def admin_upsert(req: Request, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    body = await req.json()

    public_no = str(body.get("public_no", "")).strip()
    if not public_no:
        raise HTTPException(400, "public_no required")

    item = str(body.get("item", "")).strip()
    status = str(body.get("status", "")).strip()
    if not item or not status:
        raise HTTPException(400, "item/status required")

    owner_tg_id = body.get("owner_tg_id")
    owner_phone = body.get("owner_phone")
    services = body.get("services") or []
    price = body.get("price")
    comment = body.get("comment")

    services_json = json.dumps([str(x).strip() for x in services if str(x).strip()], ensure_ascii=False)

    p = require_pool()
    async with p.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO orders (public_no, owner_tg_id, owner_phone, item, services_json, status, price, comment, created_at, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now(), now())
            ON CONFLICT(public_no) DO UPDATE SET
              owner_tg_id=EXCLUDED.owner_tg_id,
              owner_phone=EXCLUDED.owner_phone,
              item=EXCLUDED.item,
              services_json=EXCLUDED.services_json,
              status=EXCLUDED.status,
              price=EXCLUDED.price,
              comment=EXCLUDED.comment,
              updated_at=now()
            """,
            public_no, owner_tg_id, owner_phone, item, services_json, status, price, comment
        )

    return {"ok": True}
