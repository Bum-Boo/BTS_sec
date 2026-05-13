import { RateLimiter } from "../scanner-core/rate-limiter";
import { redactSecrets } from "../scanner-core/redaction";
import { assertUrlInScope } from "../scanner-core/target";
import { HttpResponseSnapshot, SafeHttpClient, SafeRequestInit, UrlTarget } from "../scanner-core/types";

export class ScopedHttpClient implements SafeHttpClient {
  private readonly limiter: RateLimiter;

  constructor(
    private readonly target: UrlTarget,
    requestsPerSecond: number,
    private readonly timeoutMs: number
  ) {
    this.limiter = new RateLimiter(requestsPerSecond);
  }

  async request(pathOrUrl: string, init: SafeRequestInit = {}): Promise<HttpResponseSnapshot> {
    const url = new URL(pathOrUrl, this.target.url);
    assertUrlInScope(this.target, url);

    return this.limiter.schedule(async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await fetch(url, {
          method: init.method ?? "GET",
          headers: {
            "User-Agent": "bts-sec/0.1 defensive-audit",
            ...init.headers
          },
          redirect: "manual",
          signal: controller.signal
        });

        const headers = headersToRecord(response.headers);
        const bodySnippet = init.method === "HEAD"
          ? undefined
          : await readLimitedBody(response, init.bodySnippetLimit ?? 1024);

        return {
          url: url.toString(),
          status: response.status,
          headers,
          bodySnippet: bodySnippet ? redactSecrets(bodySnippet) : undefined
        };
      } finally {
        clearTimeout(timeout);
      }
    });
  }
}

function headersToRecord(headers: Headers): Record<string, string> {
  const record: Record<string, string> = {};
  headers.forEach((value, key) => {
    record[key.toLowerCase()] = value;
  });
  return record;
}

async function readLimitedBody(response: Response, limit: number): Promise<string> {
  if (!response.body || limit <= 0) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";

  while (received < limit) {
    const { done, value } = await reader.read();
    if (done || !value) {
      break;
    }
    const remaining = limit - received;
    const chunk = value.slice(0, remaining);
    received += chunk.byteLength;
    text += decoder.decode(chunk, { stream: true });
    if (value.byteLength > remaining) {
      await reader.cancel();
      break;
    }
  }

  text += decoder.decode();
  return text;
}
