# IAM policy allows all actions or all resources

What the rule checks: customer-managed IAM policies with an allow statement that uses a wildcard for
every action, or a wildcard for every resource together with at least one action that can change or
expose data. Read-only actions on every resource are not flagged, except a few reads that return
secrets or object data.

Why it matters: a policy that allows everything, or allows an action everywhere, gives whoever holds
it far more power than the job needs. If the user or role is compromised, the damage is not limited.

What the fix involves: no patch is generated. Narrowing a policy safely needs real usage data: which
actions are used and on which resources. The user has to review the statements in the evidence and
decide what to keep.

What can break: removing permissions that something still uses. No usage data is collected here, so
the effect of narrowing a policy is unknown.

How to talk about it: be clear that this is guidance, not a ready-made fix, and point the reader to
the statements named in the evidence.
