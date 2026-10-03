# IAM permissions allow privilege escalation

What the rule checks: a policy, or all the policies of a role together, that grant every permission
of at least one known privilege escalation method. These are well-known combinations, for example
being able to create a new policy version or attach a stronger policy to oneself, that let a
limited identity give itself more access.

Why it matters: an identity with such a combination is effectively close to an administrator, even if
its policy does not say so. Wildcards in the policy can grant these permissions without naming them.

What the fix involves: no patch is generated. The user has to decide which permissions are really
needed, remove the others, or limit them to specific resources and add conditions. The evidence lists
each matched method with its permissions, and says when a grant is limited to specific resources or
has a condition.

What can break: removing permissions that automation still uses. Permission boundaries, service
control policies and resource policies are not checked, so one of them may already block the method.
That makes this finding a heuristic, not proof that escalation works.

How to talk about it: describe it as a risk to review, and be honest that it is not verified.
