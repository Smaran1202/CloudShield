"""Hand-written resources for E4. They are synthetic: not taken from any real account. The rules
run on them, so the details that the fix templates read come from the real rule code."""

from cloudshield.scanner.common import make_resource

ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
SOME_ON = {**ALL_OFF, "BlockPublicAcls": True, "BlockPublicPolicy": True}
AES = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
OPEN = ["0.0.0.0/0"]
V6 = ["::/0"]
MIXED = ["10.0.0.0/8", "0.0.0.0/0"]


def s3(fixture: str, name: str, region: str, block, encryption, versioning: str) -> tuple:
    attributes = {"public_access_block": block, "encryption": encryption, "versioning": versioning}
    return fixture, make_resource(name, "S3", region, name, attributes)


def rule(protocol: str, from_port=None, to_port=None, v4=(), v6=()) -> dict:
    """An inbound rule in the shape that describe_security_groups returns."""
    permission = {"IpProtocol": protocol, "UserIdGroupPairs": [], "PrefixListIds": []}
    if from_port is not None:
        permission["FromPort"] = from_port
        permission["ToPort"] = to_port
    permission["IpRanges"] = [{"CidrIp": cidr} for cidr in v4]
    permission["Ipv6Ranges"] = [{"CidrIpv6": cidr} for cidr in v6]
    return permission


def sg(fixture: str, group_id: str, region: str, *inbound: dict) -> tuple:
    attributes = {"vpc_id": "vpc-0abc1234", "inbound": list(inbound), "outbound": []}
    return fixture, make_resource(group_id, "Security Group", region, group_id, attributes)


FIXTURES = [
    s3("bucket-no-settings", "plain-bucket", "us-east-1", None, None, "Disabled"),
    s3("bucket-partial-block", "partial-block", "eu-west-1", SOME_ON, AES, "Suspended"),
    s3("bucket-dotted-name", "logs.example.com", "ap-southeast-2", ALL_OFF, None, "Disabled"),
    s3("bucket-numeric-start", "123-start-bucket", "us-west-2", None, AES, "Disabled"),
    s3("bucket-longest-name", "b" * 63, "us-east-2", ALL_OFF, None, "Suspended"),
    sg("sg-ssh-ipv4", "sg-0a1b2c3d", "us-east-1", rule("tcp", 22, 22, OPEN)),
    sg("sg-ssh-ipv6", "sg-0a1b2c3e", "us-east-1", rule("tcp", 22, 22, v6=V6)),
    sg("sg-all-ports-tcp", "sg-0a1b2c3f", "eu-west-1", rule("tcp", 0, 65535, OPEN)),
    sg("sg-port-range-20-30", "sg-0a1b2c40", "eu-west-1", rule("tcp", 20, 30, OPEN)),
    sg("sg-all-protocols", "sg-0a1b2c41", "us-west-2", rule("-1", v4=OPEN, v6=V6)),
    sg("sg-numeric-protocol", "sg-0a1b2c42", "us-west-2", rule("6", 22, 22, OPEN)),
    sg("sg-two-rules", "sg-0a1b2c43", "us-east-1", rule("tcp", 22, 22, OPEN), rule("-1", v6=V6)),
    sg("sg-open-and-private", "sg-0a1b2c44", "us-east-1", rule("tcp", 22, 22, MIXED)),
]
