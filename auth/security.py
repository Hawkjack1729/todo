import os
from datetime import datetime, timedelta
from typing import Dict, Optional

import jwt
import pyotp
from dotenv import load_dotenv
from passlib.context import CryptContext

# Load environment variables
load_dotenv()


class SecurityManager:
    # JWT Configuration
    SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    # Password Hashing
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    # OTP Configuration
    OTP_EXPIRATION_MINUTES = int(os.getenv("OTP_EXPIRATION_MINUTES", 10))
    OTP_LENGTH = int(os.getenv("OTP_LENGTH", 6))

    @classmethod
    def create_access_token(cls, data: Dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        expire = datetime.utcnow() + (
            expires_delta or timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, cls.SECRET_KEY, algorithm=cls.ALGORITHM)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return cls.pwd_context.hash(password)

    @classmethod
    def generate_otp(cls, email: str) -> str:
        totp = pyotp.TOTP(pyotp.random_base32(), digits=cls.OTP_LENGTH)
        return totp.now()

    @classmethod
    def verify_otp(cls, otp: str, stored_otp: str) -> bool:
        return otp == stored_otp
