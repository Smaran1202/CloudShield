# Security group allows SSH or all traffic from the internet

What the rule checks: the inbound rules of a security group. This finding means a rule lets the whole
internet, any IPv4 or IPv6 address, reach the SSH port (or a port range that includes it), or every
port and protocol.

Why it matters: remote login ports that are open to everyone are probed constantly. Anyone can try
to guess passwords or use a stolen key against the instances that use the group. A rule that allows
all traffic opens every service on those instances.

What the fix does: it removes the open rule from the group. Other rules in the group stay as they
are. The CLI patch removes exactly the open rule described in the evidence.

What can break: anyone who connects through that rule loses access, including administrators using
SSH from changing addresses, and any service that was reachable through an allow-all rule. Flow logs
are not collected, so who really connects is unknown. A safer way in is a session manager service, a
VPN, or a rule limited to known addresses.

How to talk about it: the evidence is the rule configuration. It does not prove that anyone has
connected or that the instances can be reached from the internet. Only mention ports and address
ranges that appear in the evidence or the patch.
