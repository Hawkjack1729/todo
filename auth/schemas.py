import os
import re
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, validator

load_dotenv()


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


@validator("password")
def validate_password(cls, password):
    min_length = int(os.getenv("PASSWORD_MIN_LENGTH", 8))
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters")
    if os.getenv(
        "PASSWORD_REQUIRE_UPPERCASE", "true"
    ).lower() == "true" and not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if os.getenv(
        "PASSWORD_REQUIRE_LOWERCASE", "true"
    ).lower() == "true" and not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if os.getenv(
        "PASSWORD_REQUIRE_NUMBERS", "true"
    ).lower() == "true" and not re.search(r"\d", password):
        raise ValueError("Password must contain at least one number")
    if os.getenv(
        "PASSWORD_REQUIRE_SPECIAL_CHARS", "true"
    ).lower() == "true" and not re.search(r"[@$!%*?&#]", password):
        raise ValueError("Password must contain at least one special character")
    return password


class UserResponse(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True


class TokenData(BaseModel):
    email: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str
