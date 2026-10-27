// Plain meanings for terms that appear in imported findings. Each one is written in CloudShield's
// own words. A term is shown only when the finding's own text uses it.
export interface Term {
  term: string;
  pattern: RegExp;
  meaning: string;
}

export const GLOSSARY: Term[] = [
  {
    term: "Least privilege",
    pattern: /least[- ]privilege/i,
    meaning: "Give a person or program only the permissions it needs, and nothing more.",
  },
  {
    term: "Separation of duties",
    pattern: /separation of duties/i,
    meaning: "No one person can do every step of a sensitive job alone.",
  },
  {
    term: "Permissions boundary",
    pattern: /permissions? boundar/i,
    meaning:
      "A limit on the most that an identity can ever be allowed, whatever its policies say.",
  },
  {
    term: "Lateral movement",
    pattern: /lateral(ly)? (movement|access)/i,
    meaning:
      "An attacker who is in one place using it to reach other parts of the account.",
  },
  {
    term: "MFA",
    pattern: /\bMFA\b|multi-factor/i,
    meaning: "A second proof of identity at sign-in, such as a code or a security key.",
  },
  {
    term: "Service-linked role",
    pattern: /service[- ]linked role/i,
    meaning:
      "A role that an AWS service owns and uses on your behalf. You usually cannot change it.",
  },
  {
    term: "AWS managed policy",
    pattern: /AWS[- ]managed polic/i,
    meaning:
      "A permission set that AWS writes and keeps up to date. You can attach it but not edit it.",
  },
  {
    term: "Customer managed policy",
    pattern: /customer[- ]managed polic/i,
    meaning: "A permission set that you write and can edit.",
  },
  {
    term: "Network ACL",
    pattern: /network ACL|\bNACLs?\b/i,
    meaning: "A list of allow and deny rules for traffic into and out of a subnet.",
  },
  {
    term: "Security group",
    pattern: /security groups?/i,
    meaning:
      "A set of rules that decides which traffic may reach a server or other resource.",
  },
  {
    term: "Stateless",
    pattern: /stateless/i,
    meaning:
      "Each packet is judged on its own, so allowing a request does not allow its reply.",
  },
  {
    term: "Block Public Access",
    pattern: /block public access/i,
    meaning: "An S3 setting that stops buckets and objects from being made public.",
  },
  {
    term: "Last accessed information",
    pattern: /last[- ]accessed/i,
    meaning:
      "A record of when an identity last used a service, to see what it really needs.",
  },
  {
    term: "Security key",
    pattern: /security keys?|passkeys?|FIDO/i,
    meaning:
      "A physical device or passkey used as a second sign-in step. It is hard to phish.",
  },
];

export function termsIn(text: string): Term[] {
  return GLOSSARY.filter((entry) => entry.pattern.test(text));
}
