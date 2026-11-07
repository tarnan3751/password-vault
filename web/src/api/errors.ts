import type { ErrorBody } from './types.ts';

/** An error response from the server, carrying the API error code (api.md). */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly currentVersion?: number;
  readonly retryAfterMs?: number;
  constructor(status: number, body: ErrorBody['error']) {
    // The server's message is shown as-is; it never contains secrets (they never reach the server).
    super(body.message || body.code);
    this.name = 'ApiError';
    this.status = status;
    this.code = body.code;
    this.currentVersion = body.current_version;
    this.retryAfterMs = body.retry_after_ms;
  }
}

/** No node could be reached (or all failed with something retryable). */
export class NetworkError extends Error {
  /** True if a mutation may or may not have been applied (a request was sent but no definite answer came back). */
  readonly outcomeUnknown: boolean;
  constructor(message: string, outcomeUnknown = false) {
    super(message);
    this.name = 'NetworkError';
    this.outcomeUnknown = outcomeUnknown;
  }
}
