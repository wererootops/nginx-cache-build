#!/usr/bin/env bash
# audit-cve.sh - Interpret CVE artifacts from a nginx-cache-build pipeline run.
#
# Reads grype JSON and trivy JSON reports plus syft and declarative SBOMs
# from the artifact directory produced by `gh run download`. Emits logfmt
# records on stdout covering:
#   - SBOM metadata (component counts, source: syft vs declarative)
#   - Per-scanner totals and per-severity breakdown
#   - Top severity findings (Critical and High) with fix availability
#   - Grype vs trivy delta on the official image (double-check comparison)
#
# Usage:
#   audit-cve.sh <artifact-dir> [--top N]
#
# Where <artifact-dir> is the path produced by:
#   gh run download <RUN_ID> -D <artifact-dir>
#
# Expects this layout (from nginx-ci workflow):
#   <dir>/grype-report/*.grype.json            # grype on official image
#   <dir>/sast-report/*.sast.json              # trivy on official image
#   <dir>/sbom-official/*.sbom.cdx.json        # syft SBOM of official image
#   <dir>/<base>-bundle/*.grype.json           # grype on build SBOM
#   <dir>/<base>-bundle/*.sbom.cdx.json        # declarative build SBOM
#
# Output: logfmt on stdout, script errors on stderr.
#
# Design notes:
# - Pure interpretation, no data collection. Run `gh run download` first.
# - Trivy on build SBOM is intentionally not consulted; trivy bails out on
#   declarative SBOMs with pkg:generic PURLs (see workflow header for details).
# - Exits 0 even when findings exist. Gating is the caller's job.

set -euo pipefail

# --- helpers ---

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log()  { printf 'time=%s %s\n' "$(ts)" "$*"; }
elog() { printf 'time=%s %s\n' "$(ts)" "$*" >&2; }

info() {
  local event="$1"; shift
  log "level=info event=$event $*"
}

warn() {
  local event="$1"; shift
  log "level=warn event=$event $*"
}

fail() {
  local event="$1"; shift
  elog "level=error event=$event $*"
  exit 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail missing_tool tool="$1"
}

# --- argument parsing ---

TOP_N=10
ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --top)
      TOP_N="${2:-10}"
      shift 2
      ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

[ ${#ARGS[@]} -ge 1 ] || fail usage hint="audit-cve.sh <artifact-dir> [--top N]"

AUDIT_DIR="${ARGS[0]}"
[ -d "$AUDIT_DIR" ] || fail dir_not_found dir="$AUDIT_DIR"

require jq
require sort
require comm
require find

# --- locate artifacts ---

GRYPE_OFFICIAL="$(find "$AUDIT_DIR" -path '*/grype-report/*.grype.json' 2>/dev/null | head -1)"
TRIVY_OFFICIAL="$(find "$AUDIT_DIR" -path '*/sast-report/*.sast.json' 2>/dev/null | head -1)"
SBOM_OFFICIAL="$(find "$AUDIT_DIR" -path '*/sbom-official/*.sbom.cdx.json' 2>/dev/null | head -1)"
GRYPE_BUILD="$(find "$AUDIT_DIR" -path '*-bundle/*.grype.json' 2>/dev/null | head -1)"
SBOM_BUILD="$(find "$AUDIT_DIR" -path '*-bundle/*.sbom.cdx.json' 2>/dev/null | head -1)"

# --- analysis functions ---

sbom_summary() {
  local file="$1" target="$2" source="$3"
  local count name version
  count=$(jq '.components | length' "$file")
  name=$(jq -r '.metadata.component.name // "unknown"' "$file")
  version=$(jq -r '.metadata.component.version // "unknown"' "$file")
  info sbom_summary target="$target" source="$source" \
    component_count="$count" name="$name" version="$version"
}

summarize_grype() {
  local file="$1" target="$2"
  local total critical high medium low negligible unknown with_fix without_fix

  total=$(jq '.matches | length' "$file")
  critical=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$file")
  high=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$file")
  medium=$(jq '[.matches[] | select(.vulnerability.severity == "Medium")] | length' "$file")
  low=$(jq '[.matches[] | select(.vulnerability.severity == "Low")] | length' "$file")
  negligible=$(jq '[.matches[] | select(.vulnerability.severity == "Negligible")] | length' "$file")
  unknown=$(jq '[.matches[] | select(.vulnerability.severity == "Unknown")] | length' "$file")
  with_fix=$(jq '[.matches[] | select(.vulnerability.fix.versions | length > 0)] | length' "$file")
  without_fix=$(jq '[.matches[] | select(.vulnerability.fix.versions | length == 0)] | length' "$file")

  info scanner_summary scanner=grype target="$target" \
    total="$total" critical="$critical" high="$high" medium="$medium" low="$low" \
    negligible="$negligible" unknown="$unknown" \
    with_fix="$with_fix" without_fix="$without_fix"
}

summarize_trivy() {
  local file="$1" target="$2"
  local total critical high medium low unknown with_fix

  total=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$file")
  critical=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$file")
  high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$file")
  medium=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$file")
  low=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$file")
  unknown=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")] | length' "$file")
  with_fix=$(jq '[.Results[]?.Vulnerabilities[]? | select((.FixedVersion // "") | length > 0)] | length' "$file")

  info scanner_summary scanner=trivy target="$target" \
    total="$total" critical="$critical" high="$high" medium="$medium" low="$low" \
    unknown="$unknown" with_fix="$with_fix"
}

top_findings_grype() {
  local file="$1" target="$2" limit="$3"

  jq -r --argjson lim "$limit" '
    [.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")]
    | sort_by(.vulnerability.severity, .artifact.name)
    | .[0:$lim]
    | .[]
    | [.vulnerability.id, .vulnerability.severity, .artifact.name, .artifact.version, ((.vulnerability.fix.versions // []) | join(";"))]
    | @tsv' "$file" \
  | while IFS=$'\t' read -r cve sev pkg ver fix; do
      info top_cve scanner=grype target="$target" \
        cve="$cve" severity="$sev" pkg="$pkg" version="$ver" fix="${fix:-none}"
    done
}

top_findings_trivy() {
  local file="$1" target="$2" limit="$3"

  jq -r --argjson lim "$limit" '
    [.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")]
    | sort_by(.Severity, .PkgName)
    | .[0:$lim]
    | .[]
    | [.VulnerabilityID, .Severity, .PkgName, .InstalledVersion, (.FixedVersion // "")]
    | @tsv' "$file" \
  | while IFS=$'\t' read -r cve sev pkg ver fix; do
      info top_cve scanner=trivy target="$target" \
        cve="$cve" severity="$sev" pkg="$pkg" version="$ver" fix="${fix:-none}"
    done
}

compare_scanners() {
  local grype_file="$1" trivy_file="$2" target="$3"
  local tmpdir
  tmpdir=$(mktemp -d)

  jq -r '.matches[].vulnerability.id' "$grype_file" | sort -u > "$tmpdir/grype.txt"
  jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' "$trivy_file" | sort -u > "$tmpdir/trivy.txt"

  local grype_total trivy_total only_grype only_trivy in_both overlap_pct
  grype_total=$(wc -l < "$tmpdir/grype.txt")
  trivy_total=$(wc -l < "$tmpdir/trivy.txt")
  only_grype=$(comm -23 "$tmpdir/grype.txt" "$tmpdir/trivy.txt" | wc -l)
  only_trivy=$(comm -13 "$tmpdir/grype.txt" "$tmpdir/trivy.txt" | wc -l)
  in_both=$(comm -12 "$tmpdir/grype.txt" "$tmpdir/trivy.txt" | wc -l)

  # Overlap as percentage of trivy findings covered by grype.
  # Trivy is the baseline; grype is the candidate replacement.
  # 100% means grype catches everything trivy does (plus extras possibly).
  if [ "$trivy_total" -gt 0 ]; then
    overlap_pct=$(( in_both * 100 / trivy_total ))
  else
    overlap_pct=0
  fi

  info delta_comparison scanner_a=grype scanner_b=trivy target="$target" \
    grype_total="$grype_total" trivy_total="$trivy_total" \
    only_grype="$only_grype" only_trivy="$only_trivy" in_both="$in_both" \
    grype_covers_trivy_pct="$overlap_pct"

  rm -rf "$tmpdir"
}

# --- main ---

info audit_start dir="$AUDIT_DIR" top_n="$TOP_N"

# SBOM metadata first (context for the scans that follow)
if [ -n "$SBOM_OFFICIAL" ] && [ -f "$SBOM_OFFICIAL" ]; then
  sbom_summary "$SBOM_OFFICIAL" official syft
else
  warn missing_artifact name=sbom-official
fi

if [ -n "$SBOM_BUILD" ] && [ -f "$SBOM_BUILD" ]; then
  sbom_summary "$SBOM_BUILD" build declarative
else
  warn missing_artifact name=sbom-build
fi

# Official image scans (primary + double-check)
if [ -n "$GRYPE_OFFICIAL" ] && [ -f "$GRYPE_OFFICIAL" ]; then
  summarize_grype "$GRYPE_OFFICIAL" official
  top_findings_grype "$GRYPE_OFFICIAL" official "$TOP_N"
else
  warn missing_artifact name=grype-official
fi

if [ -n "$TRIVY_OFFICIAL" ] && [ -f "$TRIVY_OFFICIAL" ]; then
  summarize_trivy "$TRIVY_OFFICIAL" official
  top_findings_trivy "$TRIVY_OFFICIAL" official "$TOP_N"
else
  warn missing_artifact name=trivy-official
fi

# Cross-scanner comparison on the official image
if [ -n "$GRYPE_OFFICIAL" ] && [ -n "$TRIVY_OFFICIAL" ] \
   && [ -f "$GRYPE_OFFICIAL" ] && [ -f "$TRIVY_OFFICIAL" ]; then
  compare_scanners "$GRYPE_OFFICIAL" "$TRIVY_OFFICIAL" official
fi

# Build scan (grype only, trivy not viable here)
if [ -n "$GRYPE_BUILD" ] && [ -f "$GRYPE_BUILD" ]; then
  summarize_grype "$GRYPE_BUILD" build
  top_findings_grype "$GRYPE_BUILD" build "$TOP_N"
else
  warn missing_artifact name=grype-build
fi

info audit_done dir="$AUDIT_DIR"
