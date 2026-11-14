import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.database.base import Base
from app.database.database import SessionLocal, engine
from app.database.migrations import upgrade_sqlite_schema

# Import models so SQLAlchemy registers their tables before create_all().
from app.models import ai_analysis, finding, project, scan, scanner_run, target  # noqa: F401
from app.services.ai_analyst import recover_interrupted_analyses
from app.services.orchestrator import recover_interrupted_assessments

logger = logging.getLogger("autopentest")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Convenient for the hackathon starter. Use Alembic migrations before production.
    Base.metadata.create_all(bind=engine)
    if settings.database_url.startswith("sqlite"):
        for stmt in upgrade_sqlite_schema(engine):
            logger.warning("Schema upgraded: %s", stmt)
    interrupted = recover_interrupted_assessments(SessionLocal)
    if interrupted:
        logger.warning("Marked %d interrupted assessment(s) as failed", interrupted)
    if recover_interrupted_analyses(SessionLocal):
        logger.warning("Marked interrupted AI analyses as failed")
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.3.0",
    description="Backend API for authorized web application security assessments.",
    debug=settings.debug,
    lifespan=lifespan,
)

if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,  # explicit origins only, no "*"
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", tags=["System"])
def root():
    return {
        "name": settings.app_name,
        "status": "online",
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy"}
