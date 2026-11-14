from fastapi import APIRouter

from app.api.routes import analysis, assessments, findings, projects, scans, targets, ui

api_router = APIRouter()
api_router.include_router(projects.router)
api_router.include_router(targets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(assessments.router)
api_router.include_router(analysis.router)
# Web UI adapter (sentinel-security frontend contract); additive, no overlaps.
api_router.include_router(ui.router)
