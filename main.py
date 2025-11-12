import os
import time
import hmac
import json
import base64
from hashlib import sha256
from typing import List, Optional, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utils
# -----------------------------

def oid_to_str(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d and isinstance(d["_id"], ObjectId):
        d["id"] = str(d.pop("_id"))
    # convert nested ObjectIds if any
    for k, v in list(d.items()):
        if isinstance(v, ObjectId):
            d[k] = str(v)
    return d


def sign_token(payload: dict, secret: str) -> str:
    data = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), data, sha256).digest()
    return base64.urlsafe_b64encode(data).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")


def verify_token(token: str, secret: str) -> dict:
    try:
        data_b64, sig_b64 = token.split(".")
        # pad
        pad = lambda s: s + "=" * (-len(s) % 4)
        data = base64.urlsafe_b64decode(pad(data_b64))
        sig = base64.urlsafe_b64decode(pad(sig_b64))
        expected = hmac.new(secret.encode(), data, sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Invalid signature")
        payload = json.loads(data.decode())
        if payload.get("exp") and time.time() > payload["exp"]:
            raise ValueError("Token expired")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e


# -----------------------------
# Auth
# -----------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int


def get_current_admin(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    secret = os.getenv("ADMIN_SECRET", "change-me")
    payload = verify_token(token, secret)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return payload


@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    if req.username != admin_user or req.password != admin_pass:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    exp = int(time.time()) + 60 * 60 * 8  # 8 hours
    token = sign_token({"sub": req.username, "role": "admin", "exp": exp}, os.getenv("ADMIN_SECRET", "change-me"))
    return LoginResponse(token=token, expires_in=exp - int(time.time()))


# -----------------------------
# Schemas (mirror backend schemas.py for viewer + validation)
# -----------------------------
class CategoryModel(BaseModel):
    name: str
    description: Optional[str] = None
    order: int = Field(0, ge=0)
    is_active: bool = True


class ItemModel(BaseModel):
    title: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    affiliate_url: str
    price: Optional[float] = Field(None, ge=0)
    category_id: Optional[str] = None
    tags: List[str] = []
    is_active: bool = True


# -----------------------------
# Public endpoints
# -----------------------------
@app.get("/")
def root():
    return {"message": "Affiliate Catalog API"}


@app.get("/categories")
def list_categories(include_inactive: bool = False):
    filt = {} if include_inactive else {"is_active": True}
    cats = db.category.find(filt).sort("order", 1)
    return [oid_to_str(c) for c in cats]


@app.get("/items")
def list_items(category_id: Optional[str] = None, q: Optional[str] = None, include_inactive: bool = False):
    filt: Dict[str, Any] = {} if include_inactive else {"is_active": True}
    if category_id:
        try:
            filt["category_id"] = category_id
        except Exception:
            pass
    if q:
        # simple case-insensitive search on title or tags
        filt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"tags": {"$elemMatch": {"$regex": q, "$options": "i"}}},
        ]
    items = db.item.find(filt).sort("_id", -1)
    return [oid_to_str(i) for i in items]


# -----------------------------
# Admin endpoints (CRUD)
# -----------------------------
@app.post("/admin/categories", dependencies=[Depends(get_current_admin)])
def create_category(payload: CategoryModel):
    _id = create_document("category", payload)
    doc = db.category.find_one({"_id": ObjectId(_id)})
    return oid_to_str(doc)


@app.put("/admin/categories/{category_id}", dependencies=[Depends(get_current_admin)])
def update_category(category_id: str, payload: CategoryModel):
    from datetime import datetime, timezone
    result = db.category.update_one({"_id": ObjectId(category_id)}, {"$set": {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    doc = db.category.find_one({"_id": ObjectId(category_id)})
    return oid_to_str(doc)


@app.delete("/admin/categories/{category_id}", dependencies=[Depends(get_current_admin)])
def delete_category(category_id: str):
    # Also optionally unset category_id on items
    db.item.update_many({"category_id": category_id}, {"$set": {"category_id": None}})
    res = db.category.delete_one({"_id": ObjectId(category_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"success": True}


@app.post("/admin/items", dependencies=[Depends(get_current_admin)])
def create_item(payload: ItemModel):
    _id = create_document("item", payload)
    doc = db.item.find_one({"_id": ObjectId(_id)})
    return oid_to_str(doc)


@app.put("/admin/items/{item_id}", dependencies=[Depends(get_current_admin)])
def update_item(item_id: str, payload: ItemModel):
    from datetime import datetime, timezone
    result = db.item.update_one({"_id": ObjectId(item_id)}, {"$set": {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    doc = db.item.find_one({"_id": ObjectId(item_id)})
    return oid_to_str(doc)


@app.delete("/admin/items/{item_id}", dependencies=[Depends(get_current_admin)])
def delete_item(item_id: str):
    res = db.item.delete_one({"_id": ObjectId(item_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"success": True}


# Existing diagnostics
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
