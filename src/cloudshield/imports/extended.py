import logging
from collections.abc import Callable

from sqlalchemy.orm import Session

from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, ScanRow
from cloudshield.imports.importer import RunInfo, import_parsed
from cloudshield.imports.parser import AlreadyImported, ImportRejected, parse_bytes
from cloudshield.imports.runner import PERMISSION_HINT, ExtendedError, RunOutput

logger = logging.getLogger(__name__)

RUNNING = "Running extended checks (this can take several minutes)"
IMPORTING = "Importing results"


def outcome(status: str, message: str, hint: str | None = None) -> dict:
    return {"status": status, "message": message, "hint": hint}


def run_extended_stage(
    session: Session,
    scan: ScanRow,
    regions: list[str],
    extended_function: Callable[[list[str]], RunOutput],
) -> dict:
    """Runs the extended checks and imports their results into the scan being saved.

    It never raises: whatever goes wrong is returned as the outcome, so the CloudShield scan
    itself still completes."""
    store.set_progress(session, scan.id, RUNNING)
    try:
        output = extended_function(regions)
    except ExtendedError as exc:
        return outcome(exc.status, exc.message, exc.hint)
    except Exception as exc:
        logger.exception("Extended checks failed")
        message = f"The extended checks failed unexpectedly ({type(exc).__name__})."
        return outcome("failed", message, "See the log of the API server.")

    store.set_progress(session, scan.id, IMPORTING)
    run = RunInfo("dashboard", output.duration_seconds, output.services, output.regions, scan.id)
    try:
        parsed = parse_bytes(output.content)
        result = import_parsed(session, parsed, ACCOUNT_ID, output.file_name, run, scan)
    except AlreadyImported:
        session.rollback()
        return outcome(
            "ok", "Extended checks: already imported (the results are identical to an earlier run)."
        )
    except ImportRejected as exc:
        session.rollback()
        message = f"The results file was rejected: {exc}"
        return outcome("failed", message, "See docs/extended-checks.md.")
    except Exception as exc:
        logger.exception("Importing the extended results failed")
        session.rollback()
        message = f"The results could not be imported ({type(exc).__name__})."
        return outcome("failed", message, "See the log of the API server.")

    counts = result["counts"]
    message = (
        f"Extended checks: {counts['imported']} imported, {counts['resolved']} resolved, "
        f"{counts['passed']} passed"
    )
    if output.saw_permission_errors:
        return outcome("ok", message + ". Prowler reported errors.", PERMISSION_HINT)
    return outcome("ok", message)
