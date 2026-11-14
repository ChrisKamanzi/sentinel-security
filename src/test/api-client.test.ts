import { afterEach, describe, expect, it, vi } from "vitest";

// client.ts reads VITE_API_BASE_URL at import time, so each case re-imports it.
async function loadClient(env: { base?: string; ssr?: boolean; proc?: Record<string, string> }) {
  vi.resetModules();
  vi.stubEnv("VITE_API_BASE_URL", env.base ?? "");
  vi.stubEnv("SSR", env.ssr ?? false);
  for (const key of ["API_INTERNAL_URL", "API_PROXY_TARGET"]) delete process.env[key];
  Object.assign(process.env, env.proc ?? {});
  return import("@/lib/api/client");
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  delete process.env["API_INTERNAL_URL"];
  delete process.env["API_PROXY_TARGET"];
});

describe("API client URLs", () => {
  it("is in demo mode when VITE_API_BASE_URL is unset", async () => {
    const c = await loadClient({});
    expect(c.isDemoMode).toBe(true);
  });

  it("uses /api/v1 exactly once in the browser (Vite proxy path)", async () => {
    const c = await loadClient({ base: "/api/v1" });
    expect(c.isDemoMode).toBe(false);
    expect(c.apiUrl("/dashboard/summary")).toBe("/api/v1/dashboard/summary");
  });

  it("ignores a trailing slash on the base", async () => {
    const c = await loadClient({ base: "/api/v1/" });
    expect(c.apiUrl("/findings")).toBe("/api/v1/findings");
  });

  it("calls FastAPI on 127.0.0.1:8001 during SSR by default", async () => {
    const c = await loadClient({ base: "/api/v1", ssr: true });
    expect(c.internalApiOrigin()).toBe("http://127.0.0.1:8001");
    expect(c.apiUrl("/assessments")).toBe("http://127.0.0.1:8001/api/v1/assessments");
  });

  it("lets API_INTERNAL_URL override the SSR origin", async () => {
    const c = await loadClient({
      base: "/api/v1",
      ssr: true,
      proc: { API_INTERNAL_URL: "http://backend:9000/", API_PROXY_TARGET: "http://ignored:1" },
    });
    expect(c.apiUrl("/reports")).toBe("http://backend:9000/api/v1/reports");
  });

  it("falls back to API_PROXY_TARGET for SSR when API_INTERNAL_URL is unset", async () => {
    const c = await loadClient({
      base: "/api/v1",
      ssr: true,
      proc: { API_PROXY_TARGET: "http://127.0.0.1:9100" },
    });
    expect(c.apiUrl("/reports")).toBe("http://127.0.0.1:9100/api/v1/reports");
  });

  it("uses an absolute base as-is in both browser and SSR", async () => {
    const browser = await loadClient({ base: "https://api.example.com/api/v1" });
    expect(browser.apiUrl("/findings")).toBe("https://api.example.com/api/v1/findings");
    const ssr = await loadClient({ base: "https://api.example.com/api/v1", ssr: true });
    expect(ssr.apiUrl("/findings")).toBe("https://api.example.com/api/v1/findings");
  });
});

describe("service layer paths", () => {
  it("never doubles the /api prefix", async () => {
    vi.resetModules();
    vi.stubEnv("VITE_API_BASE_URL", "/api/v1");
    vi.stubEnv("SSR", false);
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { api } = await import("@/lib/api/services");

    await api.getDashboard();
    await api.listAssessments();
    await api.getScan("s1");
    await api.listFindings();
    await api.getFinding("f1");
    await api.listReports();
    await api.createAssessment({
      target: "https://x.test",
      name: "x",
      authorized: true,
      profile: "quick",
      modules: [],
      maxRps: 5,
    });
    await api.getScanAnalysis("s1");
    await api.startScanAnalysis("s1");
    // No chat endpoint exists on the backend: the demo chat must not call one.
    await expect(api.askAnalyst([{ role: "user", content: "hi" }])).rejects.toThrow("demo mode");

    const calls = fetchMock.mock.calls.map((call) => {
      const [url, init] = call as unknown as [string, RequestInit | undefined];
      return `${init?.method ?? "GET"} ${url}`;
    });
    expect(calls).toEqual([
      "GET /api/v1/dashboard/summary",
      "GET /api/v1/assessments",
      "GET /api/v1/assessments/s1",
      "GET /api/v1/findings",
      "GET /api/v1/findings/f1/detail",
      "GET /api/v1/reports",
      "POST /api/v1/assessments",
      "GET /api/v1/scans/s1/analysis",
      "POST /api/v1/scans/s1/analysis",
    ]);
    expect(api.reportDownloadUrl("r1")).toBe("/api/v1/reports/r1/download");
  });
});

describe("API reliability", () => {
  it("surfaces FastAPI validation details", async () => {
    const c = await loadClient({ base: "/api/v1" });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: [{ loc: ["body", "maxRps"], msg: "Input should be greater than or equal to 1" }] }), { status: 422 })));
    await expect(c.apiFetch("/assessments")).rejects.toThrow("maxRps: Input should be greater than or equal to 1");
  });
  it("does not replace failed live reads with mock data", async () => {
    await loadClient({ base: "/api/v1" });
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    const { api } = await import("@/lib/api/services");
    await expect(api.getDashboard()).rejects.toThrow("Cannot reach the FastAPI backend");
  });
  it("times out a stalled request after 30 seconds", async () => {
    const c = await loadClient({ base: "/api/v1" });
    vi.useFakeTimers();
    try {
      vi.stubGlobal("fetch", vi.fn((_url, init: RequestInit) => new Promise((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))))));
      const check = expect(c.apiFetch("/assessments")).rejects.toThrow("within 30 seconds");
      await vi.advanceTimersByTimeAsync(30_000);
      await check;
    } finally { vi.useRealTimers(); }
  });
  it("never claims a demo scan was submitted", async () => {
    await loadClient({});
    const { api } = await import("@/lib/api/services");
    await expect(api.createAssessment({ target: "https://example.com", authorized: true, name: "test", profile: "quick", modules: [], maxRps: 10 })).rejects.toThrow("No scan was submitted");
  });
  it("connects existing target and report endpoints", async () => {
    await loadClient({ base: "/api/v1" });
    const mock = vi.fn(async (_url: string, _init?: RequestInit) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", mock);
    const { api } = await import("@/lib/api/services");
    await api.listProjects(); await api.createProject("Lab"); await api.listTargets("p1");
    await api.createTarget("p1", { name: "Lab", host: "example.com", base_url: "https://example.com", is_authorized: true });
    await api.updateTarget("t1", false); await api.listTools(); await api.listFindings("s1"); await api.downloadReport("s1");
    expect(mock.mock.calls.map((args) => args[0])).toEqual(["/api/v1/projects", "/api/v1/projects", "/api/v1/projects/p1/targets", "/api/v1/projects/p1/targets", "/api/v1/targets/t1", "/api/v1/tools", "/api/v1/findings?assessmentId=s1", "/api/v1/reports/s1/download"]);
  });
});
