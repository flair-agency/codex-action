import assert from "node:assert/strict";
import { test } from "node:test";
import {
  exchangeWifAccessToken,
  OPENAI_WIF_TOKEN_EXCHANGE_URL,
  parseWifAccessToken,
  WIF_ACCESS_TOKEN_TYPE,
  WIF_ID_TOKEN_SUBJECT_TOKEN_TYPE,
  WIF_JWT_SUBJECT_TOKEN_TYPE,
  WIF_TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/wifAuth.ts";

const now = 1_800_000_000;
const subjectToken = "synthetic.header.payload.signature";
const exchangedToken = "opaque+/=synthetic-access-token";

function exchangeInput(overrides = {}) {
  return {
    subjectToken,
    subjectTokenType: "jwt",
    identityProviderId: "synthetic-provider-id",
    serviceAccountId: "synthetic-service-account-id",
    ...overrides,
  };
}

function successfulResponse(overrides = {}) {
  return {
    access_token: exchangedToken,
    issued_token_type: WIF_ACCESS_TOKEN_TYPE,
    token_type: "Bearer",
    expires_in: 3600,
    expires_at: now + 3600,
    ...overrides,
  };
}

function response(payload, overrides = {}) {
  return {
    ok: true,
    status: 200,
    async json() {
      return payload;
    },
    ...overrides,
  };
}

test("posts the exact JWT exchange request through the injected transport", async () => {
  let call;
  const result = await exchangeWifAccessToken(
    exchangeInput(),
    async (url, request) => {
      call = { url, request };
      return response(successfulResponse());
    },
    () => now
  );

  assert.equal(call.url, OPENAI_WIF_TOKEN_EXCHANGE_URL);
  assert.equal(call.request.method, "POST");
  assert.deepEqual(call.request.headers, {
    "content-type": "application/json",
  });
  assert.deepEqual(JSON.parse(call.request.body), {
    grant_type: WIF_TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token_type: WIF_JWT_SUBJECT_TOKEN_TYPE,
    subject_token: subjectToken,
    identity_provider_id: "synthetic-provider-id",
    service_account_id: "synthetic-service-account-id",
  });
  assert.deepEqual(result, {
    accessToken: exchangedToken,
    expiresIn: 3600,
    expiresAt: now + 3600,
  });
});

test("supports the documented id_token subject-token type", async () => {
  let body;
  await exchangeWifAccessToken(
    exchangeInput({ subjectTokenType: "id_token" }),
    async (_url, request) => {
      body = JSON.parse(request.body);
      return response(successfulResponse());
    },
    () => now
  );

  assert.equal(body.subject_token_type, WIF_ID_TOKEN_SUBJECT_TOKEN_TYPE);
});

test("preserves opaque bearer values and does not assume JWT access-token syntax", () => {
  assert.deepEqual(
    parseWifAccessToken(successfulResponse(), now),
    {
      accessToken: exchangedToken,
      expiresIn: 3600,
      expiresAt: now + 3600,
    }
  );
});

test("rejects missing request inputs without including their values in errors", async () => {
  const canary = "synthetic-subject-token-canary";
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput({ identityProviderId: "", subjectToken: canary }),
      async () => response(successfulResponse()),
      () => now
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      assert.equal(error.message.includes("synthetic-provider-id"), false);
      return /missing or invalid/.test(error.message);
    }
  );
});

test("fails closed on HTTP errors without reading or exposing response bodies", async () => {
  const canary = "synthetic-error-body-canary";
  let jsonRead = false;
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput(),
      async () => ({
        ok: false,
        status: 403,
        async json() {
          jsonRead = true;
          throw new Error(canary);
        },
      }),
      () => now
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      return error.message === "WIF token exchange failed (HTTP 403)";
    }
  );
  assert.equal(jsonRead, false);
});

test("redacts injected transport and JSON parser errors", async () => {
  const canary = "synthetic-transport-secret-canary";
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput({ subjectToken: canary }),
      async () => {
        throw new Error(`transport echoed ${canary}`);
      },
      () => now
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      return error.message === "WIF token exchange transport failed";
    }
  );

  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput(),
      async () => ({
        ok: true,
        status: 200,
        async json() {
          throw new Error(`parser echoed ${canary}`);
        },
      }),
      () => now
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      return error.message === "WIF token exchange returned invalid JSON";
    }
  );
});

test("rejects expired or malformed exchange responses", () => {
  const badResponses = [
    successfulResponse({ expires_at: now }),
    successfulResponse({ expires_at: now - 1 }),
    successfulResponse({ expires_in: 0 }),
    successfulResponse({ expires_in: 1.5 }),
    successfulResponse({ expires_in: 1, expires_at: now + 3600 }),
    successfulResponse({ expires_in: 1, expires_at: now + 3601 }),
    successfulResponse({ expires_in: 3601 }),
    successfulResponse({ token_type: "MAC" }),
    successfulResponse({ access_token: " " }),
    successfulResponse({ issued_token_type: "synthetic-wrong-type" }),
    null,
    [],
  ];

  for (const badResponse of badResponses) {
    assert.throws(() => parseWifAccessToken(badResponse, now));
  }
});

test("accepts an absolute expiry shortened by exchange delivery time", () => {
  assert.deepEqual(
    parseWifAccessToken(
      successfulResponse({ expires_in: 3600, expires_at: now + 3599 }),
      now
    ),
    {
      accessToken: exchangedToken,
      expiresIn: 3600,
      expiresAt: now + 3599,
    }
  );
});

test("rejects an invalid injected clock without making a transport call", async () => {
  let calls = 0;
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput(),
      async () => {
        calls += 1;
        return response(successfulResponse());
      },
      () => Number.NaN
    ),
    /Invalid WIF exchange clock/
  );
  assert.equal(calls, 0);
});

test("redacts errors thrown by the injected clock", async () => {
  const canary = "synthetic-clock-error-canary";
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput(),
      async () => response(successfulResponse()),
      () => {
        throw new Error(canary);
      }
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      return error.message === "Invalid WIF exchange clock";
    }
  );
});

test("checks token expiry after the injected exchange has completed", async () => {
  let currentTime = now;
  await assert.rejects(
    exchangeWifAccessToken(
      exchangeInput(),
      async () => {
        currentTime = now + 3600;
        return response(successfulResponse());
      },
      () => currentTime
    ),
    /Invalid or expired WIF token exchange response/
  );
});
