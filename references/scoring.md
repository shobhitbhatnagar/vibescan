# Risk scoring

The 0–100 risk score is a weighted sum of findings, capped at 100:

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |
| info | 0 |

Overall band from the score:

| Score | Band |
|---|---|
| 70–100 | critical |
| 40–69 | high |
| 15–39 | medium |
| 1–14 | low |
| 0 | clean |

This is deliberately simple and transparent — a single critical finding (a live secret,
an injection sink) pushes a project into at least the "high" band, which matches how the
original VibeScan treated direct RCE/exfil vectors. Adjust the weights in
`scripts/normalize.py` (`SEV_WEIGHT`) if you want a different risk appetite.
