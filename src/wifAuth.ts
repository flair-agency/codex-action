/** OpenAI's documented JWT workload-identity token-exchange endpoint. */
export const OPENAI_WIF_TOKEN_EXCHANGE_URL =
  "https://auth.openai.com/oauth/token";

export const WIF_TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";
export const WIF_JWT_SUBJECT_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:jwt";
export const WIF_ID_TOKEN_SUBJECT_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:id_token";
export const WIF_ACCESS_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:access_token";
/**
 * API WIF lifetime cap documented at
 * developers.openai.com/api/reference/workload-identity-federation.
 */
export const MAX_WIF_ACCESS_TOKEN_LIFETIME_SECONDS = 3600;

export type WifSubjectTokenType = "jwt" | "id_token";

export interface WifExchangeInput {
  subjectToken: string;
  subjectTokenType: WifSubjectTokenType;
  identityProviderId: string;
  serviceAccountId: string;
}

export interface WifExchangeRequest {
  method: "POST";
  headers: Readonly<Record<string, string>>;
  body: string;
}

export interface WifExchangeHttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type WifExchangeTransport = (
  url: string,
  request: WifExchangeRequest
) => Promise<WifExchangeHttpResponse>;

export interface WifAccessToken {
  /** Opaque bearer value. Callers must not assume a token encoding. */
  accessToken: string;
  /** Lifetime from token issuance, in seconds. */
  expiresIn: number;
  /** Absolute Unix timestamp in seconds, as returned by OpenAI. */
  expiresAt: number;
}

/** Build the exact OpenAI JWT token-exchange request without performing I/O. */
export function createWifExchangeRequest(
  input: WifExchangeInput
): WifExchangeRequest {
  requireNonEmpty(input.subjectToken);
  requireNonEmpty(input.identityProviderId);
  requireNonEmpty(input.serviceAccountId);

  const subjectTokenType =
    input.subjectTokenType === "jwt"
      ? WIF_JWT_SUBJECT_TOKEN_TYPE
      : input.subjectTokenType === "id_token"
        ? WIF_ID_TOKEN_SUBJECT_TOKEN_TYPE
        : null;
  if (subjectTokenType == null) {
    throw new Error("Unsupported WIF subject-token type");
  }

  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: WIF_TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token_type: subjectTokenType,
      subject_token: input.subjectToken,
      identity_provider_id: input.identityProviderId,
      service_account_id: input.serviceAccountId,
    }),
  };
}

/** Validate an exchange response against an injected transport and clock.
 *
 * This function deliberately has no default fetch implementation and reads no
 * process environment. A production credential holder must be supplied and
 * reviewed separately before this contract can be wired into the Action.
 */
export async function exchangeWifAccessToken(
  input: WifExchangeInput,
  transport: WifExchangeTransport,
  readCurrentEpochSeconds: () => number
): Promise<WifAccessToken> {
  readClock(readCurrentEpochSeconds);

  const request = createWifExchangeRequest(input);
  let response: WifExchangeHttpResponse;
  try {
    response = await transport(OPENAI_WIF_TOKEN_EXCHANGE_URL, request);
  } catch {
    // Do not propagate transport errors: implementations may include request
    // bodies, subject tokens, response bodies, or other credential material.
    throw new Error("WIF token exchange transport failed");
  }

  if (!response.ok) {
    const status = Number.isInteger(response.status) ? response.status : 0;
    throw new Error(`WIF token exchange failed (HTTP ${status})`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("WIF token exchange returned invalid JSON");
  }

  // Exchange and response delivery consume token lifetime. Sample the injected
  // clock only after the response has arrived and been parsed.
  return parseWifAccessToken(payload, readClock(readCurrentEpochSeconds));
}

/** Validate the documented bearer and expiration fields without logging data. */
export function parseWifAccessToken(
  payload: unknown,
  nowEpochSeconds: number
): WifAccessToken {
  if (!Number.isSafeInteger(nowEpochSeconds) || nowEpochSeconds < 0) {
    throw new Error("Invalid WIF exchange clock");
  }
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Invalid WIF token exchange response");
  }

  const response = payload as Record<string, unknown>;
  const accessToken = response.access_token;
  const tokenType = response.token_type;
  const expiresIn = response.expires_in;
  const expiresAt = response.expires_at;

  if (
    typeof accessToken !== "string" ||
    accessToken.trim().length === 0 ||
    typeof tokenType !== "string" ||
    tokenType.toLowerCase() !== "bearer" ||
    !Number.isSafeInteger(expiresIn) ||
    (expiresIn as number) <= 0 ||
    (expiresIn as number) > MAX_WIF_ACCESS_TOKEN_LIFETIME_SECONDS ||
    !Number.isSafeInteger(expiresAt) ||
    (expiresAt as number) <= nowEpochSeconds
  ) {
    throw new Error("Invalid or expired WIF token exchange response");
  }

  if (
    response.issued_token_type !== undefined &&
    response.issued_token_type !== WIF_ACCESS_TOKEN_TYPE
  ) {
    throw new Error("Invalid WIF token exchange response");
  }

  return {
    accessToken,
    expiresIn: expiresIn as number,
    expiresAt: expiresAt as number,
  };
}

function requireNonEmpty(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("WIF exchange input is missing or invalid");
  }
}

function readClock(readCurrentEpochSeconds: () => number): number {
  let nowEpochSeconds: number;
  try {
    nowEpochSeconds = readCurrentEpochSeconds();
  } catch {
    throw new Error("Invalid WIF exchange clock");
  }
  if (!Number.isSafeInteger(nowEpochSeconds) || nowEpochSeconds < 0) {
    throw new Error("Invalid WIF exchange clock");
  }
  return nowEpochSeconds;
}
