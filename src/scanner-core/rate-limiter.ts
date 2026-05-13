export class RateLimiter {
  private nextAvailable = 0;
  private readonly intervalMs: number;

  constructor(requestsPerSecond: number) {
    if (!Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0) {
      throw new Error("rateLimitRps must be greater than 0");
    }
    this.intervalMs = Math.ceil(1000 / requestsPerSecond);
  }

  async schedule<T>(task: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const waitMs = Math.max(0, this.nextAvailable - now);
    this.nextAvailable = Math.max(now, this.nextAvailable) + this.intervalMs;

    if (waitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    return task();
  }
}
