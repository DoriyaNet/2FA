import { describe, expect, it } from "vitest";
import {
  SESSION_COOKIE_MAX_AGE_SECONDS,
  sessionCookieMaxAge,
} from "../../server/session.js";

const NOW = 1_700_000_000_000;

describe("session cookie lifetime", () => {
  it("keeps non-expiring GitHub tokens for the default session lifetime", () => {
    expect(
      sessionCookieMaxAge(
        {
          accessToken: "ghu_test",
          refreshToken: null,
          expiresAt: null,
          refreshTokenExpiresAt: null,
        },
        NOW,
      ),
    ).toBe(SESSION_COOKIE_MAX_AGE_SECONDS);
  });

  it("caps the cookie at a non-refreshable access-token expiry", () => {
    expect(
      sessionCookieMaxAge(
        {
          accessToken: "ghu_test",
          refreshToken: null,
          expiresAt: NOW + 90_000,
          refreshTokenExpiresAt: null,
        },
        NOW,
      ),
    ).toBe(90);
  });

  it("uses the refresh-token expiry when it is longer", () => {
    expect(
      sessionCookieMaxAge(
        {
          accessToken: "ghu_test",
          refreshToken: "ghr_test",
          expiresAt: NOW + 60_000,
          refreshTokenExpiresAt: NOW + 3_600_000,
        },
        NOW,
      ),
    ).toBe(3_600);
  });

  it("expires immediately when the available token lifetime has ended", () => {
    expect(
      sessionCookieMaxAge(
        {
          accessToken: "ghu_test",
          refreshToken: "ghr_test",
          expiresAt: NOW - 2_000,
          refreshTokenExpiresAt: NOW - 1_000,
        },
        NOW,
      ),
    ).toBe(1);
  });
});
