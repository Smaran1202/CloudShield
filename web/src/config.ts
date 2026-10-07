// How often a running scan and the API are checked. After a failed health check the next check
// comes sooner. Tests make these very short.
export const config = { scanPollMs: 2000, healthPollMs: 30000, healthRetryMs: 2000 };
