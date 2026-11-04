import pytest

from cloudshield.auth import __main__ as cli
from cloudshield.auth.passwords import parse_hash, verify_password

PASSWORD = "a long enough password"


def answers(monkeypatch, *typed: str) -> list[str]:
    """Replaces getpass, so no terminal is needed. Returns the prompts that were shown."""
    prompts = []
    replies = iter(typed)

    def fake(prompt: str = "") -> str:
        prompts.append(prompt)
        return next(replies)

    monkeypatch.setattr(cli.getpass, "getpass", fake)
    return prompts


def test_hash_password_asks_twice_and_prints_only_the_hash(monkeypatch, capsys):
    prompts = answers(monkeypatch, PASSWORD, PASSWORD)

    code = cli.main(["hash-password"])

    printed = capsys.readouterr()
    assert code == 0
    assert prompts == ["Password: ", "Password again: "]
    assert PASSWORD not in printed.out + printed.err
    stored = printed.out.strip()
    assert len(printed.out.strip().splitlines()) == 1
    parse_hash(stored)
    assert verify_password(PASSWORD, stored)


def test_two_different_passwords_make_no_hash(monkeypatch, capsys):
    answers(monkeypatch, PASSWORD, PASSWORD + "x")

    code = cli.main(["hash-password"])

    printed = capsys.readouterr()
    assert code == 1
    assert printed.out == ""
    assert "not the same" in printed.err
    assert PASSWORD not in printed.err


def test_a_short_password_is_refused_before_it_is_asked_again(monkeypatch, capsys):
    prompts = answers(monkeypatch, "short")

    code = cli.main(["hash-password"])

    printed = capsys.readouterr()
    assert code == 1
    assert prompts == ["Password: "]
    assert printed.out == ""
    assert "at least 12 characters" in printed.err
    assert "short" not in printed.err


def test_secret_prints_a_long_random_value_each_time(capsys):
    cli.main(["secret"])
    first = capsys.readouterr().out.strip()
    cli.main(["secret"])
    second = capsys.readouterr().out.strip()

    assert len(first.encode()) >= 32
    assert first != second


def test_an_unknown_command_is_an_error():
    with pytest.raises(SystemExit):
        cli.main(["nothing"])
