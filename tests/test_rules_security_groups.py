from cloudshield.rules.security_groups import check_open_ssh_or_all
from cloudshield.scanner.common import make_resource

ANYWHERE = [{"CidrIp": "0.0.0.0/0"}]


def group(inbound=None) -> dict:
    attributes = {} if inbound is None else {"vpc_id": "vpc-1", "inbound": inbound, "outbound": []}
    return make_resource("sg-1", "Security Group", "ap-southeast-2", "web", attributes)


def tcp(from_port: int, to_port: int, ip_ranges=ANYWHERE, ipv6_ranges=()) -> dict:
    return {
        "IpProtocol": "tcp",
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": ip_ranges,
        "Ipv6Ranges": list(ipv6_ranges),
    }


def test_ssh_open_to_the_internet_is_a_finding():
    hits = check_open_ssh_or_all([group([tcp(22, 22)])])

    assert len(hits) == 1
    assert hits[0].details["rules"][0]["exposes"] == "SSH (port 22)"
    assert hits[0].details["rules"][0]["cidrs"] == ["0.0.0.0/0"]


def test_ssh_open_to_ipv6_anywhere_is_a_finding():
    permission = tcp(22, 22, ip_ranges=[], ipv6_ranges=[{"CidrIpv6": "::/0"}])

    hits = check_open_ssh_or_all([group([permission])])

    assert hits[0].details["rules"][0]["cidrs"] == ["::/0"]


def test_port_range_that_includes_22_is_a_finding():
    assert len(check_open_ssh_or_all([group([tcp(0, 1024)])])) == 1


def test_port_range_that_does_not_include_22_has_no_finding():
    assert check_open_ssh_or_all([group([tcp(1000, 2000)])]) == []


def test_all_protocols_open_to_the_internet_is_a_finding():
    permission = {"IpProtocol": "-1", "IpRanges": ANYWHERE, "Ipv6Ranges": []}

    hits = check_open_ssh_or_all([group([permission])])

    assert hits[0].details["rules"][0]["exposes"] == "all ports and protocols"


def test_ssh_from_a_private_range_has_no_finding():
    permission = tcp(22, 22, ip_ranges=[{"CidrIp": "10.0.0.0/8"}])

    assert check_open_ssh_or_all([group([permission])]) == []


def test_https_open_to_the_internet_has_no_finding():
    assert check_open_ssh_or_all([group([tcp(443, 443)])]) == []


def test_udp_on_port_22_has_no_finding():
    permission = {**tcp(22, 22), "IpProtocol": "udp"}

    assert check_open_ssh_or_all([group([permission])]) == []


def test_two_open_rules_give_one_finding_listing_both():
    permissions = [tcp(22, 22), {"IpProtocol": "-1", "IpRanges": ANYWHERE, "Ipv6Ranges": []}]

    hits = check_open_ssh_or_all([group(permissions)])

    assert len(hits) == 1
    assert len(hits[0].details["rules"]) == 2


def test_unknown_inbound_rules_are_not_a_finding():
    assert check_open_ssh_or_all([group()]) == []
