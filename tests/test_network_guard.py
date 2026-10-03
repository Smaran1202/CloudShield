import socket

import pytest


def test_a_lookup_of_an_outside_host_is_blocked():
    with pytest.raises(RuntimeError, match="blocked in tests"):
        socket.getaddrinfo("generativelanguage.googleapis.com", 443)


def test_a_direct_connection_to_an_outside_address_is_blocked():
    with socket.socket() as outside:
        with pytest.raises(RuntimeError, match="blocked in tests"):
            outside.connect(("203.0.113.10", 443))


def test_the_machine_itself_can_still_be_reached():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        with socket.socket() as client:
            client.connect(server.getsockname())
