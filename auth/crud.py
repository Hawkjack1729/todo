import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from core.security import SecurityManager

from .models import User
from .schemas import UserCreate


def create_user(db: Session, user: UserCreate):
    hashed_password = SecurityManager.get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()
