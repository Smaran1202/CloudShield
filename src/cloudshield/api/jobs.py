import logging
from collections.abc import Callable

import boto3
from sqlalchemy.orm import Session, sessionmaker

from cloudshield.db import store
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.scan import scan_account

logger = logging.getLogger(__name__)


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
) -> None:
    with session_factory() as session:
        store.mark_running(session, scan_id)
        try:
            result = scan_function(regions)
            store.set_progress(session, scan_id, "Running rules and saving findings")
            findings = score_findings(run_rules(result["resources"]), result, regions)
            store.save_result(session, scan_id, result, findings)
        except Exception as exc:
            # The scan runs in a background thread, so the error has to be recorded on the scan
            # row for the user to see it.
            session.rollback()
            logger.exception("Scan %s failed", scan_id)
            store.mark_failed(session, scan_id, f"{type(exc).__name__}: {exc}")
