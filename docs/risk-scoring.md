# Risk scoring and evidence

Every finding from a rule that counts toward risk gets a `risk_score` from 0 to 100 and a list of
`risk_factors` that explain it. INFO rules (currently CIS-S3-002) do not count toward risk: their
findings have `risk_score` null and no factors.

## Base score

| Severity | Base |
|---|---|
| CRITICAL | 90 |
| HIGH | 70 |
| MEDIUM | 40 |
| LOW | 20 |
| INFO | 5 |

## Adjustments

Adjustments use only facts already in the scan's resources. No extra AWS calls are made. The score
is the base plus the adjustments, capped at 100. Each factor is
`{factor, adjustment, reason, certainty}`.

| Factor | Applies to | +Points | Condition |
|---|---|---|---|
| exposure | any finding on an S3 bucket | 15 | Block Public Access is missing or has a setting off |
| exposure | any finding on a security group | 15 | an inbound rule allows 0.0.0.0/0 or ::/0 |
| attached | any finding on a security group | 10 | attached to a running EC2 instance in the scan |
| privilege | any finding on an IAM policy | 10 | attached to at least one user, role or group |

When the condition is false the factor is still listed with `adjustment` 0 and a reason, for example
"Not attached to any running EC2 instance in this scan."

## Certainty

- `verified`: the fact was read from AWS in this scan (for example the four public access block
  settings, or the policies a policy is attached to).
- `heuristic`: a conclusion the scan cannot fully prove. "Not attached to a running instance" is
  heuristic, because load balancers, databases and other services can also use a security group and
  are not checked. Privilege escalation evidence is heuristic, because permission boundaries,
  service control policies and resource policies are not evaluated.
- `unknown`: the data needed was not available, for example a call failed or the region was not
  scanned. An unknown factor always has `adjustment` 0, so missing data never adds risk.

The exposure factors describe configuration only. They do not test whether a resource can actually
be reached.

## Environment score

`100 x (1 - product of (1 - score / 100))` over all open findings that count toward risk. Each scan
stores the result as `environment_score`, with `severity_counts` for all open findings (INFO included).
A resolved finding keeps its last score but is left out. `GET /api/risk/trend` returns one point per
completed scan.

## Evidence

Each finding has an `evidence` object with a list of `items`. An item is
`{fact, value, source, certainty}`, where `source` is the path of the field in the stored resource's
`attributes` that the value came from. Evidence is built from the resource facts the rule used. It
contains no AI-written text.
