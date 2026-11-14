/**
 * HTTP client for the AutoPentest AI FastAPI backend.
 *
 * VITE_API_BASE_URL selects the backend and must include the API prefix:
 *   - unset          → demo mode (bundled demo data, no network calls)
 *   - "/api/v1"      → local dev through the Vite proxy (see vite.config.ts)
 *   - "https://…/api/v1" → a deployed backend (needs CORS_ORIGINS on the backend)
 */
export const API_BASE_URL: string | undefined =
  import.meta.env["VITE_API_BASE_URL"]?.replace(/\/+$/, "") || undefined;
export const isDemoMode = !API_BASE_URL;

/** Backend origin used where the Vite proxy can't help (server-side rendering). */
const DEFAULT_BACKEND_ORIGIN = "http://127.0.0.1:8001";

/** Origin (no path) that SSR uses to reach FastAPI directly. */
export function internalApiOrigin(): string {
  const env = globalThis.process?.env;
  const origin = env?.["API_INTERNAL_URL"] || env?.["API_PROXY_TARGET"] || DEFAULT_BACKEND_ORIGIN;
  return origin.replace(/\/+$/, "");
}

/**
 * Base URL for a request. A relative base ("/api/v1") only works in the browser,
 * where the Vite dev server proxies it; route loaders that run during SSR need an
 * absolute URL, so they call the backend origin directly.
 */
function requestBase(): string {
  const base = API_BASE_URL ?? "";
  if (!base.startsWith("/") || !import.meta.env.SSR) return base;
  return internalApiOrigin() + base;
}

/** Absolute or proxy-relative URL for a backend path, e.g. for download links. */
export function apiUrl(path: string): string {
  return `${requestBase()}${path}`;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(path), {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = body.detail ?? msg;
    } catch {}
    throw new ApiError(res.status, typeof msg === "string" ? msg : "Request failed");
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
