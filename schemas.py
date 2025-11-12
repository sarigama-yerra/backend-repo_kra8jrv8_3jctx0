"""
Database Schemas for Shopee Affiliate Link Catalog

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name (e.g., Category -> "category").
"""
from pydantic import BaseModel, Field
from typing import Optional, List

# ----------------------------- Auth & Session -----------------------------
class AdminUser(BaseModel):
    email: str = Field(..., description="Admin email (unique)")
    name: str = Field(..., description="Admin name")
    password_hash: str = Field(..., description="SHA256 password hash")
    role: str = Field("admin", description="User role")
    is_active: bool = Field(True, description="Whether the admin is active")

class Session(BaseModel):
    user_id: str = Field(..., description="Admin user id")
    token: str = Field(..., description="Session token")
    expires_at: int = Field(..., description="Unix timestamp expiry")

# -------------------------------- Catalog ---------------------------------
class Category(BaseModel):
    name: str = Field(..., description="Category name")
    slug: str = Field(..., description="URL friendly slug")
    description: Optional[str] = Field(None, description="Short description")
    order: int = Field(0, description="Sort order")
    is_active: bool = Field(True, description="Active status")

class Product(BaseModel):
    title: str = Field(..., description="Product name")
    description: Optional[str] = Field(None, description="Product description")
    price: Optional[float] = Field(None, ge=0, description="Price (optional)")
    image_url: Optional[str] = Field(None, description="Product image URL")
    affiliate_url: str = Field(..., description="Shopee affiliate URL")
    category_id: Optional[str] = Field(None, description="Related category _id")
    tags: List[str] = Field(default_factory=list, description="Tag list")
    is_active: bool = Field(True, description="Active status")
