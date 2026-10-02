from cloudshield.findings import Finding, make_finding_id
from cloudshield.rules import iam, privesc, s3, security_groups
from cloudshield.rules.evidence import build_evidence
from cloudshield.rules.rule import Rule

ALL_RULES = s3.RULES + security_groups.RULES + iam.RULES + privesc.RULES


def run_rules(resources: list[dict], rules: list[Rule] = ALL_RULES) -> list[Finding]:
    live = [
        r
        for r in resources
        if not (r["resource_type"] == "EC2" and r["attributes"].get("state") == "terminated")
    ]
    findings = []
    for rule in rules:
        for hit in rule.check(live):
            resource = hit.resource
            findings.append(
                Finding(
                    finding_id=make_finding_id(rule.id, resource["resource_id"], hit.variant),
                    rule_id=rule.id,
                    resource_id=resource["resource_id"],
                    resource_type=resource["resource_type"],
                    title=rule.title,
                    severity=hit.severity or rule.severity,
                    category=rule.category,
                    status="OPEN",
                    details=hit.details,
                    evidence=build_evidence(rule.id, hit.details, resource["resource_type"]),
                )
            )
    return sorted(findings, key=lambda f: (f.rule_id, f.resource_id, f.finding_id))
