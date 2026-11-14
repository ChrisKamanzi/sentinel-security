import type { NewAssessmentInput } from "./types";

/** Matches the existing FastAPI UI adapter's PROFILE_SCANNERS. */
export const profileScanners = {
  quick: ["nmap", "nuclei"],
  standard: ["nmap", "ffuf", "nuclei"],
  deep: ["nmap", "ffuf", "nuclei", "zap"],
} satisfies Record<NewAssessmentInput["profile"], string[]>;

export function validTargetUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !!url.hostname && !url.username && !url.password && !/\s/.test(value);
  } catch { return false; }
}