/** One-decimal CVSS, or null when the scanner reported no score. */
export function fmtCvss(cvss: number | null): string | null {
  return cvss == null ? null : cvss.toFixed(1);
}

export function fmtSize(sizeKb: number): string {
  return sizeKb >= 1024 ? `${(sizeKb / 1024).toFixed(1)} MB` : `${sizeKb.toFixed(1)} KB`;
}

/** Backend timestamps are UTC; SQLite may drop the zone suffix, so add it. */
export function asUtc(iso: string): string {
  return /(?:Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : `${iso}Z`;
}
