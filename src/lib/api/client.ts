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
const DEFAULT_BACKEND_ORIGIN = import.meta.env.DEV ? "http://127.0.0.1:8001" : undefined;

/** Origin (no path) that SSR uses to reach FastAPI directly. */
export function internalApiOrigin(): string {
  const env = globalThis.process?.env;
  const origin = env?.["API_INTERNAL_URL"] || env?.["API_PROXY_TARGET"] || DEFAULT_BACKEND_ORIGIN;
  if (!origin) throw new ApiError(0, "A relative API address needs API_INTERNAL_URL and a deployed reverse proxy. Use an HTTPS VITE_API_BASE_URL instead.");
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
  const res = await apiRequest(path, init);
  if (res.status === 204) return undefined as T;
  try { return await res.json() as T; }
  catch { throw new ApiError(res.status, "The backend returned an invalid JSON response."); }
}

/** Shared transport for JSON data and report downloads. Never retries mutations. */
export async function apiRequest(path: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  init?.signal?.addEventListener("abort", cancel, { once: true });
  if (init?.signal?.aborted) controller.abort();
  const timer = setTimeout(cancel, 30_000);
  try {
    const headers = new Headers(init?.headers);
    if (init?.body) headers.set("Content-Type", "application/json");
    const res = await fetch(apiUrl(path), { ...init, headers, signal: controller.signal });
  if (!res.ok) {
    let msg = res.statusText || "Request failed";
    try {
      const body = await res.json();
      const detail: unknown = body.detail;
      if (typeof detail === "string") msg = detail;
      else {
        const errors = Array.isArray(detail) ? detail : (detail && typeof detail === "object" && "errors" in detail ? detail.errors : undefined);
        if (Array.isArray(errors)) msg = errors.map((e: { loc?: unknown[]; msg?: string }) => `${e.loc?.filter((v) => v !== "body").join(".") || "Input"}: ${e.msg || "Invalid value"}`).join("; ");
      }
    } catch {}
    throw new ApiError(res.status, msg);
  }
    // Consume the body within the timeout, including streamed responses.
    const body = await res.blob();
    return new Response(res.status === 204 ? null : body, { status: res.status, statusText: res.statusText, headers: res.headers });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted) throw new ApiError(0, init?.signal?.aborted ? "Request cancelled." : "The backend did not respond within 30 seconds. Check scan status before submitting again.");
    throw new ApiError(0, "Cannot reach the FastAPI backend. Check its address, availability, and allowed browser origins.");
  } finally {
    clearTimeout(timer);
    init?.signal?.removeEventListener("abort", cancel);
  }
}
