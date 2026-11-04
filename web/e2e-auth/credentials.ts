// Made up for these tests. They are given to a throwaway API on another port, never to anything
// real. The API gets only the salted hashes, which the Playwright config makes with the project's
// own code; the secret is made again at random each time.
export const OWNER_PASSWORD = "e2e-owner-password-for-the-login-test";
export const VIEWER_PASSWORD = "e2e-viewer-password-for-the-login-test";

export const DB_NAME = "e2e-auth.db";
export const API_PORT = "8012";
export const WEB_PORT = "5184";
