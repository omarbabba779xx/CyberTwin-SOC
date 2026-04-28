"""Background task modules — import to auto-register with @register_task."""

from backend.jobs.tasks import coverage as coverage  # noqa: F401
from backend.jobs.tasks import retention as retention  # noqa: F401
