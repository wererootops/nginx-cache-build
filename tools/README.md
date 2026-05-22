# nginx-cache-build / tools

Operational scripts for inspecting CI artifacts produced by the
`nginx-ci` workflow. Pure interpretation: these scripts read what
you already downloaded with `gh run download`, they don't talk to
GitHub or to any registry.

Design philosophy follows the rest of the homelab:

- **Separation of collection and analysis.** Collection is `gh run
  download`. Analysis is what these scripts do. Two phases, two
  tools.
- **logfmt output.** Structured, one fact per line, grep and awk
  friendly, append-safe.
- **No data mutation.** Scripts read JSON files, never write to
  them.
- **Offline-safe.** Once artifacts are local, audits work without
  network.

## Scripts

### `audit-cve.sh`

Interpret CVE artifacts from a pipeline run. Reads grype JSON,
trivy JSON, the syft SBOM of the official image and the
declarative build SBOM. Emits a logfmt summary covering SBOM
metadata, per-scanner totals, per-severity breakdown, grype vs
trivy delta on the official image and top severity findings with
fix availability.

#### Workflow

1. Trigger a run (or pick an existing one):
   ```bash
   gh workflow run nginx-ci.yml -f run_new_build=true -f run_smoke_compiled=true
   ```
2. Find the run ID:
   ```bash
   gh run list --workflow=nginx-ci.yml --limit 3
   ```
3. Download all artifacts into a working directory:
   ```bash
   gh run download <RUN_ID> -D /tmp/build-audit
   ```
4. Run the audit:
   ```bash
   tools/audit-cve.sh /tmp/build-audit
   ```

#### Options

- `--top N`: number of top severity findings shown per
  scanner+target. Default 10.
- `-h`, `--help`: print the script header inline.

#### Output events

All output is logfmt on stdout. Script errors go to stderr.

| Event | Fields | Meaning |
|---|---|---|
| `audit_start` | `dir`, `top_n` | Audit run begins |
| `sbom_summary` | `target`, `source`, `component_count`, `name`, `version` | SBOM metadata |
| `scanner_summary` | `scanner`, `target`, `total`, `critical`, `high`, `medium`, `low`, ..., `with_fix`, `without_fix` | Per-scanner counts and severity breakdown |
| `top_cve` | `scanner`, `target`, `cve`, `severity`, `pkg`, `version`, `fix` | One finding worth seeing |
| `delta_comparison` | `scanner_a`, `scanner_b`, `target`, `grype_total`, `trivy_total`, `only_grype`, `only_trivy`, `in_both`, `grype_covers_trivy_pct` | Cross-scanner overlap |
| `missing_artifact` | `name` | Expected artifact not found (warning) |
| `audit_done` | `dir` | Audit complete |

`target` is either `official` (the nginx:VERSION-alpine image
scanned upstream) or `build` (the declarative SBOM of the
aarch64-musl build produced by this pipeline).

#### Filtering the audit output

Only the High and Critical findings:
```bash
tools/audit-cve.sh /tmp/build-audit \
  | grep 'event=top_cve' \
  | grep -E 'severity=(Critical|High)'
```

Only scanner summaries (compact comparison table):
```bash
tools/audit-cve.sh /tmp/build-audit | grep 'event=scanner_summary'
```

Persist audit and errors separately:
```bash
tools/audit-cve.sh /tmp/build-audit > /tmp/audit.log 2> /tmp/audit.err
```

## Direct jq queries on the raw reports

When you want detail beyond the summary, query the JSON reports
directly. After `gh run download` the layout under `<audit-dir>`
is:

```
<audit-dir>/
├── grype-report/*.grype.json              # grype on official image
├── sast-report/*.sast.json                # trivy on official image
├── sbom-official/*.sbom.cdx.json          # syft SBOM of official image
├── <base>-bundle/*.grype.json             # grype on declarative build SBOM
├── <base>-bundle/*.sbom.cdx.json          # declarative build SBOM
└── <base>/                                # release candidate (publish output)
```

### Severity vocabulary

Note the difference between scanners. Use the right case in `jq
select`:

- **grype**: `Critical`, `High`, `Medium`, `Low`, `Negligible`,
  `Unknown` (title case)
- **trivy**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`
  (uppercase)

### Grype reports

Count CVEs by severity:
```bash
jq -r '[.matches[] | .vulnerability.severity]
  | group_by(.)
  | map("\(.[0]): \(length)")[]' file.grype.json
```

Critical and High sorted by fixability then severity (fixable
first, so you see actionable items at the top):
```bash
jq -r '[.matches[]
  | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")]
  | sort_by(-((.vulnerability.fix.versions // []) | length), .vulnerability.severity, .artifact.name)
  | .[]
  | [.vulnerability.severity, .vulnerability.id, .artifact.name, .artifact.version, ((.vulnerability.fix.versions // []) | join(",") | (. // "none"))]
  | @tsv' file.grype.json | column -t -s $'\t'
```

Only fixable CVEs (the actionable subset):
```bash
jq -r '.matches[]
  | select(.vulnerability.fix.versions | length > 0)
  | [.vulnerability.severity, .vulnerability.id, .artifact.name, .artifact.version, (.vulnerability.fix.versions | join(","))]
  | @tsv' file.grype.json | sort | column -t -s $'\t'
```

CVE count per package (which packages carry the most risk):
```bash
jq -r '.matches[] | .artifact.name' file.grype.json | sort | uniq -c | sort -rn
```

Lookup a specific CVE in detail:
```bash
jq '.matches[] | select(.vulnerability.id == "CVE-2026-XXXXX")' file.grype.json
```

### Trivy reports

Count by severity:
```bash
jq -r '[.Results[]?.Vulnerabilities[]? | .Severity]
  | group_by(.)
  | map("\(.[0]): \(length)")[]' file.sast.json
```

Critical and High with fix version:
```bash
jq -r '[.Results[]?.Vulnerabilities[]?
  | select(.Severity == "CRITICAL" or .Severity == "HIGH")]
  | sort_by(.Severity, .PkgName)
  | .[]
  | [.Severity, .VulnerabilityID, .PkgName, .InstalledVersion, (.FixedVersion // "")]
  | @tsv' file.sast.json | column -t -s $'\t'
```

Set of CVE IDs for diff against grype:
```bash
jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' file.sast.json | sort -u
```

### SBOM inspection

Components catalogued by syft in the official image, by type:
```bash
jq '[.components[] | {name, version, type}] | sort_by(.type, .name)' sbom-official/*.sbom.cdx.json
```

Library components only (the security-relevant subset, files are
noise from the syft file cataloger):
```bash
jq '[.components[] | select(.type == "library") | {name, version}] | sort_by(.name)' sbom-official/*.sbom.cdx.json
```

The full declarative build SBOM:
```bash
jq '.metadata.component, .components' <base>-bundle/*.sbom.cdx.json
```

## Cross-scanner diff (manual)

Compare grype vs trivy CVE sets on the same target:
```bash
GRYPE_FILE=/tmp/build-audit/grype-report/*.grype.json
TRIVY_FILE=/tmp/build-audit/sast-report/*.sast.json

jq -r '.matches[].vulnerability.id' $GRYPE_FILE | sort -u > /tmp/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' $TRIVY_FILE | sort -u > /tmp/trivy-cves.txt

echo "grype: $(wc -l < /tmp/grype-cves.txt) unique CVEs"
echo "trivy: $(wc -l < /tmp/trivy-cves.txt) unique CVEs"
echo "Only grype:"; comm -23 /tmp/grype-cves.txt /tmp/trivy-cves.txt
echo "Only trivy:"; comm -13 /tmp/grype-cves.txt /tmp/trivy-cves.txt
echo "In both:";    comm -12 /tmp/grype-cves.txt /tmp/trivy-cves.txt
```

`audit-cve.sh` does this automatically as the
`delta_comparison` event, but the manual version lets you inspect
the specific CVE IDs.

## Why no trivy on the build SBOM

`build-native` generates a declarative CycloneDX SBOM listing the
three components linked into the binary (`nginx`, `pcre2`,
`musl`). Each component carries `purl` and `cpe`.

Grype matches via CPE which is ecosystem-agnostic, so it produces
findings against the declared versions.

Trivy `sbom` mode is OS-package-centric: it expects PURLs in
`pkg:apk/...`, `pkg:deb/...` or `pkg:rpm/...` form, or an OS
context in metadata. Generic CPE-based components return empty
`Results` with `OS.Family: "none"`. This is a structural mismatch
documented in the workflow header. Trivy stays in `get-official`
where it scans the alpine image natively and contributes to the
cross-scanner double-check during the migration window.

## See also

- `.github/workflows/nginx-ci.yml` - the pipeline that produces
  these artifacts. Header documents the SAST chain and the
  reasoning behind it.
- `wererootops/actions/sbom` - the composite action that runs
  syft, used by `get-official` and indirectly by the declarative
  SBOM step.
- `wererootops/actions/sast-container` - the composite action
  that runs grype, used by both `get-official` and `build-native`.
