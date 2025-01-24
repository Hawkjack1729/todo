from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.models import Base as AuthBase
from auth.routes import router as auth_router
from config.database import engine
from todos.models import Base as TodoBase
from todos.routes import router as todo_router

# Create database tables
AuthBase.metadata.create_all(bind=engine)
TodoBase.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Todo Application",
    description="A comprehensive todo management application",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(todo_router)


# Root endpoint
@app.get("/")
def root():
    return {"message": "Welcome to Todo Application"}


# Optional: Add global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return {"error": str(exc)}
