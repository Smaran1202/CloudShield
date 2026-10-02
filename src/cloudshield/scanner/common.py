from botocore.exceptions import BotoCoreError, ClientError


def make_resource(
    resource_id: str,
    resource_type: str,
    region: str | None,
    name: str,
    attributes: dict,
) -> dict:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "name": name,
        "attributes": attributes,
    }


def list_all(client, operation: str, key: str, **kwargs) -> list:
    items = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page[key])
    return items


def attempt(errors: list, where: dict, func, *args, missing_codes=(), **kwargs):
    """Call func and return (value, ok).

    ok is False when the call failed; the failure is appended to errors. An error code listed
    in missing_codes means "nothing there" and returns (None, True).
    """
    try:
        return func(*args, **kwargs), True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in missing_codes:
            return None, True
        message = str(exc)
    except BotoCoreError as exc:
        message = str(exc)
    errors.append({**where, "message": message})
    return None, False
