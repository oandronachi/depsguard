# Demo transcript

This transcript shows a direct depsguard policy check before a proposed
dependency change is applied.

Scenario:

- Proposed dependency change: `pypi:urllib3@1.26.4`
- Policy: `max_severity="medium"`
- Expected result: advisories are found and depsguard returns `BLOCK`
- PR action: attach the rendered dependency risk report and do not apply the
  dependency change

Command:

```powershell
.\.venv\Scripts\python.exe -c @'
import asyncio
import json
from depsguard.server import evaluate_dependency_policy

result = asyncio.run(
    evaluate_dependency_policy(
        "pypi",
        "urllib3",
        "1.26.4",
        max_severity="medium",
    )
)
print(json.dumps(result, indent=2))
'@
```

Transcript excerpt, line-wrapped for readability:

```text
HTTP Request:
  GET https://api.deps.dev/v3/systems/PYPI/packages/urllib3/versions/1.26.4
  "HTTP/1.1 200 OK"

HTTP Request:
  GET https://api.deps.dev/v3/advisories/GHSA-38jv-5279-wg99
  "HTTP/1.1 200 OK"

HTTP Request:
  GET https://api.deps.dev/v3/advisories/GHSA-q2q7-5pp4-w6pg
  "HTTP/1.1 200 OK"

... additional advisory detail lookups omitted for brevity ...

{
  "verdict": "BLOCK",
  "package": "pypi:urllib3@1.26.4",
  "policy_max_severity": "medium",
  "worst_severity": "high",
  "licenses": [
    "MIT"
  ],
  "advisories": [
    {
      "id": "GHSA-2xpw-w6gg-jr37",
      "severity": "unknown",
      "url": "https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37"
    },
    {
      "id": "GHSA-34jh-p97f-mpxf",
      "severity": "medium",
      "url": "https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf"
    },
    {
      "id": "GHSA-38jv-5279-wg99",
      "severity": "high",
      "url": "https://osv.dev/vulnerability/GHSA-38jv-5279-wg99"
    },
    {
      "id": "GHSA-g4mx-q9vg-27p4",
      "severity": "medium",
      "url": "https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4"
    },
    {
      "id": "GHSA-gm62-xv2j-4w53",
      "severity": "unknown",
      "url": "https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53"
    },
    {
      "id": "GHSA-pq67-6m6q-mj2v",
      "severity": "medium",
      "url": "https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v"
    },
    {
      "id": "GHSA-q2q7-5pp4-w6pg",
      "severity": "high",
      "url": "https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg"
    },
    {
      "id": "GHSA-qccp-gfcp-xxvc",
      "severity": "medium",
      "url": "https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc"
    },
    {
      "id": "GHSA-v845-jxx5-vc9f",
      "severity": "medium",
      "url": "https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f"
    },
    {
      "id": "PYSEC-2021-108",
      "severity": "unknown",
      "title": "PYSEC-2021-108",
      "url": "https://osv.dev/vulnerability/PYSEC-2021-108"
    },
    {
      "id": "PYSEC-2023-192",
      "severity": "high",
      "title": "PYSEC-2023-192",
      "url": "https://osv.dev/vulnerability/PYSEC-2023-192"
    },
    {
      "id": "PYSEC-2023-212",
      "severity": "medium",
      "title": "PYSEC-2023-212",
      "url": "https://osv.dev/vulnerability/PYSEC-2023-212"
    },
    {
      "id": "PYSEC-2026-141",
      "severity": "medium",
      "title": "PYSEC-2026-141",
      "url": "https://osv.dev/vulnerability/PYSEC-2026-141"
    }
  ],
  "reason": "13 advisory(ies); worst severity 'high' exceeds policy max 'medium'."
}
```

PR-style report rendered from the policy result:

```markdown
## Dependency Gate Report

- Package: `pypi:urllib3@1.26.4`
- depsguard verdict: `BLOCK`
- Policy max severity: `medium`
- Worst severity: `high`
- Licenses: `MIT`
- Reason: 13 advisory(ies); worst severity 'high' exceeds policy max 'medium'.

### Advisories

- `GHSA-2xpw-w6gg-jr37` (`unknown`): urllib3 streaming API improperly handles
  highly compressed data. <https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37>
- `GHSA-34jh-p97f-mpxf` (`medium`): Proxy-Authorization request header is not
  stripped during cross-origin redirects.
  <https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf>
- `GHSA-38jv-5279-wg99` (`high`): decompression-bomb safeguards can be bypassed
  when following HTTP redirects. <https://osv.dev/vulnerability/GHSA-38jv-5279-wg99>
- `GHSA-g4mx-q9vg-27p4` (`medium`): request body is not stripped after a 303
  redirect changes the request method to GET.
  <https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4>
- `GHSA-gm62-xv2j-4w53` (`unknown`): urllib3 allows an unbounded number of links
  in the decompression chain. <https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53>
- `GHSA-pq67-6m6q-mj2v` (`medium`): redirects are not disabled when retries are
  disabled on `PoolManager` instantiation.
  <https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v>
- `GHSA-q2q7-5pp4-w6pg` (`high`): catastrophic backtracking in the URL authority
  parser. <https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg>
- `GHSA-qccp-gfcp-xxvc` (`medium`): sensitive headers forwarded across origins
  in proxied low-level redirects. <https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc>
- `GHSA-v845-jxx5-vc9f` (`medium`): `Cookie` header is not stripped on
  cross-origin redirects. <https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f>
- `PYSEC-2021-108` (`unknown`): <https://osv.dev/vulnerability/PYSEC-2021-108>
- `PYSEC-2023-192` (`high`): <https://osv.dev/vulnerability/PYSEC-2023-192>
- `PYSEC-2023-212` (`medium`): <https://osv.dev/vulnerability/PYSEC-2023-212>
- `PYSEC-2026-141` (`medium`): <https://osv.dev/vulnerability/PYSEC-2026-141>

### Final Outcome

**Status:** `blocked`
**Final verdict:** `BLOCK`
**Required agent action:** Do not apply the dependency change. Propose a safer
version or route to security review.
```
