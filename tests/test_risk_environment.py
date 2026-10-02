from cloudshield.risk.environment import environment_score, severity_counts


def test_no_open_findings_gives_a_zero_environment_score():
    assert environment_score([]) == 0.0


def test_one_finding_gives_its_own_score():
    assert environment_score([70]) == 70.0


def test_two_findings_combine_as_one_minus_the_product_of_what_is_left():
    # 1 - (0.30 * 0.60) = 0.82
    assert environment_score([70, 40]) == 82.0


def test_three_equal_findings_combine_without_passing_100():
    # 1 - 0.5 * 0.5 * 0.5 = 0.875
    assert environment_score([50, 50, 50]) == 87.5


def test_a_score_of_100_makes_the_environment_score_100():
    assert environment_score([100, 5]) == 100.0


def test_environment_score_does_not_depend_on_order():
    assert environment_score([20, 85, 40]) == environment_score([40, 20, 85])


def test_adding_a_finding_never_lowers_the_environment_score():
    assert environment_score([70, 5]) > environment_score([70])


def test_severity_counts_has_every_severity_even_when_zero():
    counts = severity_counts(["HIGH", "HIGH", "INFO"])

    assert counts == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 1}
