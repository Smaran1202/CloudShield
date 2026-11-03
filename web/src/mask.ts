// An AWS account id is a run of exactly 12 digits. On screen it is shown with only its last four
// digits, so a screen or a screenshot does not give the account away. This changes what is
// displayed only: stored data, API replies and copied text are not touched. A run of any other
// length is not an account id and is left as it is.
const MASK = "•".repeat(8);
const ACCOUNT_ID = /(?<!\d)\d{12}(?!\d)/g;

export function maskAccountIds(text: string): string {
  return text.replace(ACCOUNT_ID, (id) => MASK + id.slice(-4));
}
