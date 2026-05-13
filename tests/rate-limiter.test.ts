import { describe, expect, it } from "vitest";
import { RateLimiter } from "../src/scanner-core/rate-limiter";

describe("rate limiting", () => {
  it("spaces scheduled tasks according to the configured rate", async () => {
    const limiter = new RateLimiter(20);
    const timestamps: number[] = [];

    await limiter.schedule(async () => {
      timestamps.push(Date.now());
    });
    await limiter.schedule(async () => {
      timestamps.push(Date.now());
    });

    expect(timestamps[1] - timestamps[0]).toBeGreaterThanOrEqual(40);
  });
});
