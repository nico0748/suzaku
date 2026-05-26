/**
 * Suzaku Web API client.
 *
 * /api/health で発行された CSRF トークンをモジュール内にキャッシュし、
 * 以降の POST/PUT/DELETE に X-Suzaku-CSRF ヘッダとして自動付与する。
 *
 * バックエンドは同一オリジン (FastAPI から静的ファイル配信) 想定だが、
 * Vite dev server は /api/* を 127.0.0.1:8765 に proxy する。
 */

let cachedCsrfToken: string | null = null;

export interface HealthResponse {
  name: string;
  version: string;
  mode: "ro" | "rw";
  csrf_token: string;
}

/** ``GET /api/health`` を叩き、CSRF トークンをキャッシュに保存する。 */
export async function fetchHealth(): Promise<HealthResponse> {
  const resp = await fetch("/api/health");
  if (!resp.ok) {
    throw new Error(`health check failed: HTTP ${resp.status}`);
  }
  const data = (await resp.json()) as HealthResponse;
  cachedCsrfToken = data.csrf_token;
  return data;
}

/** キャッシュ済み CSRF トークン。未取得なら null。 */
export function getCsrfToken(): string | null {
  return cachedCsrfToken;
}

export interface ApiErrorBody {
  error: string;
  detail?: unknown;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorBody | null,
  ) {
    super(`API ${status}: ${body?.error ?? "unknown"}`);
    this.name = "ApiError";
  }
}

interface RequestOptions<TBody> {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: TBody;
  query?: Record<string, string | undefined>;
}

/** CSRF トークンを自動付与する汎用 fetch ラッパ。 */
export async function apiFetch<TResponse, TBody = unknown>(
  path: string,
  opts: RequestOptions<TBody> = {},
): Promise<TResponse> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (method !== "GET") {
    if (!cachedCsrfToken) {
      // bootstrap: 取得失敗時はそのまま例外を伝播させる
      await fetchHealth();
    }
    if (cachedCsrfToken) {
      headers["X-Suzaku-CSRF"] = cachedCsrfToken;
    }
  }

  const url = new URL(path, window.location.origin);
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, v);
    }
  }

  const resp = await fetch(url.toString(), {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (!resp.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = (await resp.json()) as ApiErrorBody;
    } catch {
      body = null;
    }
    throw new ApiError(resp.status, body);
  }
  return (await resp.json()) as TResponse;
}
