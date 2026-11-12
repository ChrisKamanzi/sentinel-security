/**
 * HTTP client for the AutoPentest AI FastAPI backend.
 * Set VITE_API_BASE_URL (e.g. https://api.autopentest.ai) to use the real backend.
 * When unset, services fall back to bundled demo data.
 */
export const API_BASE_URL: string | undefined = import.meta.env.VITE_API_BASE_URL;
export const isDemoMode = !API_BASE_URL;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
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
  return res.json() as Promise<T>;
}
