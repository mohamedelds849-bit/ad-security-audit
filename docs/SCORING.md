# Scoring method

**Choice: a risk score from 0 to 100 where LOWER IS BETTER**, like PingCastle, rather than a
maturity score. Reason: the audience (an SME administrator and their manager) understands
"risk 90 -> 0" immediately, and it matches the most common AD tool they may meet later.

## Formula (adaudit/scoring.py)

```
points(finding)  = 40 critical | 20 high | 10 medium | 5 low
category score   = min(100, sum of the points of the findings in that category)
global score     = round(0.5 * max(category scores) + 0.5 * mean(category scores))
level            = faible <= 20 < modéré <= 50 < élevé <= 75 < critique
```

Five categories: privileged accounts, accounts & passwords, Kerberos & delegation,
workstations/servers/network, trusts.

## Design decisions (and their trade-offs)

| Decision | Why | Trade-off |
|---|---|---|
| Points do not depend on the number of affected objects | a 2,000-user domain is not "riskier" than a 50-user one for the same misconfiguration; avoids rewarding small exports | 1 stale account and 300 stale accounts score the same (the `affected` count is shown separately) |
| Category capped at 100 | a category is either "under control" or "saturated", like PingCastle | in a neglected domain several categories hit 100 |
| Global = half worst category + half mean | PingCastle uses max only: fixing 4 categories of 5 would not move the global score. The mean alone would let one catastrophic category disappear | the global score is not directly comparable with a PingCastle score |
| Severity set per check, not per finding | simple, explainable, testable | e.g. an obsolete OS on a DC is tagged in the evidence but scored like a workstation |

## Results on the synthetic AgriSouss exports

| Export | Global | Privileged | Accounts | Kerberos | Infra | Trusts | Findings |
|---|---|---|---|---|---|---|---|
| vulnerable | 90 (critique) | 100 | 100 | 100 | 80 | 20 | 23 |
| after quick wins | 74 (élevé) | 90 | 20 | 80 | 80 | 20 | 14 |
| hardened | 0 (faible) | 0 | 0 | 0 | 0 | 0 | 0 |

These numbers come from `python -m adaudit audit data/<file>.json` and are asserted in
`tests/test_scoring.py::test_agrisouss_scores`. The hardened export is designed to pass
every check; a real domain rarely reaches 0.
