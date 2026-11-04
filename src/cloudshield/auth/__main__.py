import argparse
import getpass
import secrets
import sys

from cloudshield.auth.passwords import MIN_PASSWORD_LENGTH, hash_password


def hash_command() -> int:
    """Asks for a password twice, without echo, and prints only its hash."""
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"The password must be at least {MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        return 1
    if getpass.getpass("Password again: ") != password:
        print("The two passwords are not the same.", file=sys.stderr)
        return 1
    print(hash_password(password))
    return 0


def secret_command() -> int:
    print(secrets.token_urlsafe(48))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cloudshield.auth")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("hash-password", help="make the hash to put in OWNER_PASSWORD_HASH")
    commands.add_parser("secret", help="make a random value to put in SESSION_SECRET")
    args = parser.parse_args(argv)
    return hash_command() if args.command == "hash-password" else secret_command()


if __name__ == "__main__":
    raise SystemExit(main())
