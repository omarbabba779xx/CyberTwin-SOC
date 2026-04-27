"""HTTP route packages.

Each submodule exposes a ``router: APIRouter`` that is included by
``backend.api.main`` via ``app.include_router(...)``. This keeps the
top-level ``main.py`` thin (FastAPI app setup + middleware + lifespan)
and makes endpoints discoverable by domain.
"""
