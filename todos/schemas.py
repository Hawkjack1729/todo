from typing import Optional

from pydantic import BaseModel


class TodoBase(BaseModel):
    title: str
    description: Optional[str] = None
    completed: bool = False


class TodoCreate(TodoBase):
    pass


class TodoResponse(TodoBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True
