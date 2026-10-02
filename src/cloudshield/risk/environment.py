from cloudshield.findings import SEVERITIES


def environment_score(scores: list[int]) -> float:
    # Each open finding is an independent chance of harm, so many medium findings add up but
    # the total can never pass 100.
    remaining = 1.0
    for score in scores:
        remaining *= 1 - score / 100
    return round(100 * (1 - remaining), 1)


def severity_counts(severities: list[str]) -> dict[str, int]:
    return {severity: severities.count(severity) for severity in SEVERITIES}
