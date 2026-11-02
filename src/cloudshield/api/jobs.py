import logging
import threading
from collections.abc import Callable

import boto3
from sqlalchemy.orm import Session, sessionmaker

from cloudshield.db import store
from cloudshield.db.models import ScanRow
from cloudshield.imports.extended import run_extended_stage
from cloudshield.imports.runner import RunOutput
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.scan import scan_account

logger = logging.getLogger(__name__)


class JobLock:
    """One lock for "a scan or an import is in progress". It is taken in the request thread and
    released in the job thread, so it remembers what holds it to say so in the 409 message."""

    def __init__(self) -> None:
        self.mutex = threading.Lock()
        self.holder: str | None = None

    def take(self, kind: str) -> str | None:
        """Takes the lock without waiting. Returns None when taken, else what holds it."""
        with self.mutex:
            if self.holder is not None:
                return self.holder
            self.holder = kind
            return None

    def release(self) -> None:
        with self.mutex:
            self.holder = None


def busy_message(holder: str) -> str:
    return "An import is running." if holder == "import" else "A scan is running."


def scan_with_boto3(regions: list[str]) -> dict:
    # boto3 reads AWS_PROFILE and the rest of the standard credential chain itself.
    session = boto3.Session()
    if session.get_credentials() is None:
        raise RuntimeError("No AWS credentials found. Set AWS_PROFILE on the server.")
    return scan_account(session, regions)


def run_scan_job(
    session_factory: sessionmaker[Session],
    scan_id: int,
    regions: list[str],
    scan_function: Callable[[list[str]], dict],
    extended_function: Callable[[list[str]], RunOutput] | None = None,
    job_lock: JobLock | None = None,
) -> None:
    try:
        with session_factory() as session:
            try:
                store.mark_running(session, scan_id)
                result = scan_function(regions)
                store.set_progress(session, scan_id, "Running CloudShield rules")
                findings = score_findings(run_rules(result["resources"]), result, regions)
                if extended_function is None:
                    store.save_result(session, scan_id, result, findings)
                    return
                # Our own findings are saved first. The extended stage cannot undo them.
                store.save_result(session, scan_id, result, findings, finish=False)
                extended = run_extended_stage(
                    session, session.get(ScanRow, scan_id), regions, extended_function
                )
                store.finish_scan(session, scan_id, extended)
            except Exception as exc:
                # The scan runs in a background thread, so the error has to be recorded on the
                # scan row for the user to see it.
                session.rollback()
                logger.exception("Scan %s failed", scan_id)
                store.mark_failed(session, scan_id, f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        # Recording the failure failed too (for example "database is locked"). Try once more on
        # a fresh connection so the scan is not left queued or running.
        logger.exception("Scan %s could not be marked failed", scan_id)
        with session_factory() as fresh:
            store.mark_failed(fresh, scan_id, f"{type(exc).__name__}: {exc}")
    finally:
        # The lock was taken when the scan started and covers the extended stage and its import.
        if job_lock is not None:
            job_lock.release()
