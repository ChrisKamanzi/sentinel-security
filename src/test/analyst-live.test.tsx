import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Assessment, ScanAnalysis } from "@/lib/api/types";

// Router links need a router; plain anchors are enough here.
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
}));

const SCAN = "11111111-1111-4111-8111-111111111111";
const FINDING = "22222222-2222-4222-8222-222222222222";

const assessment = (over: Partial<Assessment> = {}): Assessment => ({
  id: SCAN,
  target: "http://127.0.0.1:3000",
  name: "Juice Shop",
  status: "completed",
  progress: 100,
  startedAt: "2026-11-14T07:00:00Z",
  finishedAt: "2026-11-14T07:10:00Z",
  riskScore: 60,
  findings: { critical: 1, high: 1, medium: 0, low: 0 },
  profile: "Quick",
  ...over,
});

const analysis = (over: Partial<ScanAnalysis> = {}): ScanAnalysis => ({
  id: "a1",
  scan_id: SCAN,
  status: "completed",
  model: "claude-opus-5-5",
  served_by_model: "claude-opus-5-5",
  fallback_used: false,
  findings_total: 3,
  findings_analyzed: 2,
  redactions: 1,
  overall_risk: "high",
  executive_summary: "Two issues need attention.",
  technical_assessment: "The admin panel is exposed.",
  result: {
    overall_risk: "high",
    executive_summary: "Two issues need attention.",
    technical_assessment: "The admin panel is exposed.",
    findings: [
      {
        finding_id: FINDING,
        finding_ref: "F1",
        title: "Exposed admin panel",
        severity: "high",
        scanner: "nuclei",
        location: "http://127.0.0.1:3000/admin",
        explanation: "The admin login is public.",
        technical_impact: "Credential attacks.",
        business_impact: "Account takeover.",
        priority: "P1",
        validity: "likely_true_positive",
        validity_rationale: "Template matched.",
        confidence_limitations: "Not exploited.",
        remediation_steps: ["Restrict by IP"],
        verification_steps: ["Request /admin from outside"],
      },
    ],
    remediation_plan: [
      {
        rank: 1,
        title: "Lock down admin",
        finding_refs: ["F1"],
        finding_ids: [FINDING],
        rationale: "Biggest exposure.",
        effort: "low",
      },
    ],
    scan_limitations: ["Unauthenticated scan only."],
    warnings: [],
  },
  error_message: null,
  created_at: "2026-11-14T07:11:00",
  started_at: "2026-11-14T07:11:01",
  completed_at: "2026-11-14T07:12:00",
  duration_seconds: 59,
  ...over,
});

type Route = { status: number; body?: unknown };

async function renderView(
  routes: Record<string, Route | (() => Route)>,
  props: { findingId?: string; scanId?: string } = {},
) {
  vi.resetModules();
  vi.stubEnv("VITE_API_BASE_URL", "/api/v1");
  vi.stubEnv("SSR", false);
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${url}`;
    const route = routes[key];
    if (!route)
      return new Response(JSON.stringify({ detail: `unexpected ${key}` }), { status: 500 });
    const r = typeof route === "function" ? route() : route;
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
  });
  vi.stubGlobal("fetch", fetchMock);
  const { ScanAnalysisView } = await import("@/components/app/ScanAnalysis");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onSelectScan = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <ScanAnalysisView {...props} onSelectScan={onSelectScan} />
    </QueryClientProvider>,
  );
  return { fetchMock, onSelectScan };
}

const calls = (fetchMock: ReturnType<typeof vi.fn>) =>
  fetchMock.mock.calls.map((c) => `${(c[1] as RequestInit | undefined)?.method ?? "GET"} ${c[0]}`);

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("ScanAnalysisView (live backend)", () => {
  it("explains when there are no assessments", async () => {
    await renderView({ "GET /api/v1/assessments": { status: 200, body: [] } });
    expect(await screen.findByText(/No assessments yet/)).toBeInTheDocument();
  });

  it("shows that an assessment has not been analyzed", async () => {
    await renderView({
      "GET /api/v1/assessments": { status: 200, body: [assessment()] },
      [`GET /api/v1/scans/${SCAN}/analysis`]: {
        status: 404,
        body: { detail: "No analysis for this scan yet" },
      },
    });
    expect(await screen.findByText(/has not been analyzed yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run AI analysis/ })).toBeEnabled();
  });

  it("renders a completed analysis from the stored result", async () => {
    await renderView(
      {
        "GET /api/v1/assessments": { status: 200, body: [assessment()] },
        [`GET /api/v1/scans/${SCAN}/analysis`]: { status: 200, body: analysis() },
      },
      { findingId: FINDING, scanId: SCAN },
    );
    expect(await screen.findByText("Two issues need attention.")).toBeInTheDocument();
    expect(screen.getByText("The admin panel is exposed.")).toBeInTheDocument();
    expect(screen.getByText("Lock down admin")).toBeInTheDocument();
    expect(screen.getByText("Restrict by IP")).toBeInTheDocument();
    expect(screen.getByText("Unauthenticated scan only.")).toBeInTheDocument();
    expect(screen.getByText(/Only the 2 highest-severity findings/)).toBeInTheDocument();
    // The linked finding is highlighted.
    expect(document.getElementById(`analysis-${FINDING}`)).toHaveClass("ring-1");
    expect(screen.getByRole("button", { name: /Run new analysis/ })).toBeEnabled();
  });

  it("shows a failed analysis with the backend's error", async () => {
    await renderView({
      "GET /api/v1/assessments": { status: 200, body: [assessment()] },
      [`GET /api/v1/scans/${SCAN}/analysis`]: {
        status: 200,
        body: analysis({
          status: "failed",
          result: null,
          error_message: "ANTHROPIC_API_KEY is not configured on the server",
        }),
      },
    });
    expect(await screen.findByText("Analysis failed")).toBeInTheDocument();
    expect(screen.getByText(/ANTHROPIC_API_KEY is not configured/)).toBeInTheDocument();
  });

  it("disables a new run while one is in progress", async () => {
    await renderView({
      "GET /api/v1/assessments": { status: 200, body: [assessment()] },
      [`GET /api/v1/scans/${SCAN}/analysis`]: {
        status: 200,
        body: analysis({ status: "running", result: null }),
      },
    });
    expect(await screen.findByText(/Claude is analyzing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run new analysis/ })).toBeDisabled();
  });

  it("disables analysis while the assessment itself is still running", async () => {
    await renderView({
      "GET /api/v1/assessments": {
        status: 200,
        body: [assessment({ status: "running", progress: 40 })],
      },
      [`GET /api/v1/scans/${SCAN}/analysis`]: { status: 404 },
    });
    expect(await screen.findByText(/still in progress/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run AI analysis/ })).toBeDisabled();
  });

  it("opens the assessment of a linked finding", async () => {
    const { fetchMock } = await renderView(
      {
        "GET /api/v1/assessments": {
          status: 200,
          body: [assessment({ id: "other", name: "Other" }), assessment()],
        },
        [`GET /api/v1/findings/${FINDING}/detail`]: {
          status: 200,
          body: { id: FINDING, assessmentId: SCAN },
        },
        [`GET /api/v1/scans/${SCAN}/analysis`]: { status: 200, body: analysis() },
        "GET /api/v1/scans/other/analysis": { status: 404 },
      },
      { findingId: FINDING },
    );
    expect(await screen.findByText("Two issues need attention.")).toBeInTheDocument();
    expect(calls(fetchMock)).toContain(`GET /api/v1/scans/${SCAN}/analysis`);
  });

  it("only starts an analysis after explicit confirmation", async () => {
    let started = false;
    const { fetchMock } = await renderView({
      "GET /api/v1/assessments": { status: 200, body: [assessment()] },
      [`GET /api/v1/scans/${SCAN}/analysis`]: () =>
        started
          ? { status: 200, body: analysis({ status: "pending", result: null }) }
          : { status: 404 },
      [`POST /api/v1/scans/${SCAN}/analysis`]: () => {
        started = true;
        return { status: 202, body: analysis({ status: "pending", result: null }) };
      },
    });
    const run = await screen.findByRole("button", { name: /Run AI analysis/ });

    fireEvent.click(run);
    expect(await screen.findByText(/uses API credits/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(calls(fetchMock).filter((c) => c.startsWith("POST"))).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: /Run AI analysis/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Run analysis" }));
    await waitFor(() =>
      expect(calls(fetchMock).filter((c) => c.startsWith("POST"))).toEqual([
        `POST /api/v1/scans/${SCAN}/analysis`,
      ]),
    );
    expect(await screen.findByText(/Analysis queued/)).toBeInTheDocument();
  });

  it("surfaces a backend refusal without retrying", async () => {
    const { fetchMock } = await renderView({
      "GET /api/v1/assessments": { status: 200, body: [assessment()] },
      [`GET /api/v1/scans/${SCAN}/analysis`]: { status: 404 },
      [`POST /api/v1/scans/${SCAN}/analysis`]: {
        status: 409,
        body: { detail: "Scan has no findings to analyze" },
      },
    });
    fireEvent.click(await screen.findByRole("button", { name: /Run AI analysis/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Run analysis" }));
    await waitFor(() =>
      expect(calls(fetchMock).filter((c) => c.startsWith("POST"))).toHaveLength(1),
    );
    expect(screen.getByText(/has not been analyzed yet/)).toBeInTheDocument();
  });
});
