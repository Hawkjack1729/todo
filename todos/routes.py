from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from auth.models import User
from config.database import get_db
from core.security import get_current_user

from .crud import create_todo, delete_todo, get_todos, update_todo
from .schemas import TodoCreate, TodoResponse

router = APIRouter(prefix="/todos", tags=["todos"])


@router.post("/", response_model=TodoResponse)
def create_new_todo(
    todo: TodoCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return create_todo(db, todo, current_user.id)


@router.get("/", response_model=List[TodoResponse])
def read_todos(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_todos(db, current_user.id, skip, limit)


@router.put("/{todo_id}", response_model=TodoResponse)
def update_existing_todo(
    todo_id: int,
    todo: TodoCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    updated_todo = update_todo(db, todo_id, todo)
    if not updated_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return updated_todo


@router.delete("/{todo_id}")
def remove_todo(
    todo_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    deleted_todo = delete_todo(db, todo_id)
    if not deleted_todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"message": "Todo deleted successfully"}
