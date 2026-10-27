import re
from urllib.parse import unquote

from sqlalchemy.orm import Session, sessionmaker

from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID
from cloudshield.imports.importer import RunInfo, import_parsed
from cloudshield.imports.parser import parse_bytes

MAX_NAME_CHARS = 100
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class ImportBusy(Exception):
    """Something else is writing imported results right now."""


def clean_file_name(header: str | None) -> str | None:
    """The base name from the X-Filename header. A path, whatever its separators, is cut off."""
    if not header:
        return None
    name = CONTROL_CHARS.sub("", unquote(header))
    name = re.split(r"[\\/]", name)[-1].strip()
    if name in ("", ".", ".."):
        return None
    return name[:MAX_NAME_CHARS]


def import_upload(
    session_factory: sessionmaker[Session], raw: bytes, file_header: str | None
) -> dict:
    """Imports a results file that the user sent from the dashboard. Raises ImportRejected."""
    parsed = parse_bytes(raw)
    with session_factory() as session:
        # A scan that is saving its own results is writing the same tables.
        if store.active_scan(session) is not None:
            raise ImportBusy("A scan is running. Import the file when it has finished.")
        return import_parsed(
            session, parsed, ACCOUNT_ID, clean_file_name(file_header), RunInfo("upload")
        )
