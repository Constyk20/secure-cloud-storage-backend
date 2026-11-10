import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from admin import router as admin_router
from auth import router as auth_router
from database import ensure_indexes
from files import router as files_router
from google_drive import router as google_storage_router
from google_oauth import router as google_router
from security import router as security_router

settings = get_settings()
logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        ensure_indexes()
    except Exception:
        logger.exception("Could not ensure MongoDB indexes at startup")
    yield


app = FastAPI(title="Secured Cloud Storage", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(files_router)
app.include_router(security_router)
app.include_router(admin_router)
app.include_router(google_router)
app.include_router(google_storage_router)


@app.get("/health")
def health():
    return {"status": "ok"}