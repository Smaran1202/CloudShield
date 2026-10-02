from cloudshield.rules.rule import Hit, Rule, of_type


def open_sources(permission: dict) -> list[str]:
    cidrs = [r["CidrIp"] for r in permission.get("IpRanges", [])]
    cidrs += [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])]
    return [cidr for cidr in cidrs if cidr in ("0.0.0.0/0", "::/0")]


def exposure(permission: dict) -> str | None:
    if permission["IpProtocol"] == "-1":
        return "all ports and protocols"
    if permission["IpProtocol"] in ("tcp", "6"):
        if permission["FromPort"] <= 22 <= permission["ToPort"]:
            return "SSH (port 22)"
    return None


def check_open_ssh_or_all(resources: list[dict]) -> list[Hit]:
    hits = []
    for group in of_type(resources, "Security Group"):
        if "inbound" not in group["attributes"]:
            continue
        open_rules = []
        for permission in group["attributes"]["inbound"]:
            reason = exposure(permission)
            cidrs = open_sources(permission)
            if reason and cidrs:
                open_rules.append(
                    {
                        "exposes": reason,
                        "protocol": permission["IpProtocol"],
                        "from_port": permission.get("FromPort"),
                        "to_port": permission.get("ToPort"),
                        "cidrs": cidrs,
                    }
                )
        if open_rules:
            hits.append(Hit(group, {"rules": open_rules}))
    return hits


RULES = [
    Rule(
        id="CIS-SG-001",
        title="Security group allows SSH or all traffic from the internet",
        severity="HIGH",
        category="Network",
        description=(
            "An inbound rule allows port 22 (including a port range that contains 22) or all "
            "ports and protocols from 0.0.0.0/0 or ::/0, so anyone on the internet can reach "
            "the port."
        ),
        fix="Restrict the source to known addresses, or use SSM Session Manager instead of SSH.",
        check=check_open_ssh_or_all,
    ),
]
