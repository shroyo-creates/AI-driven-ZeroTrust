# PBCA evaluation report

> Synthetic data: a pipeline check of the evaluation plan, not experimental results.

Config: seed=42, users=200, attacks_per_phase=300, events=5861, data=synthetic, split=train months 0-3, test month 4

## RQ1 / RQ2 — login phase

| Setup | ROC-AUC | TPR@1%FPR | TPR@5%FPR | Detected | Step-ups /100 genuine | Restricted genuine % | Looser than d_P |
|---|---|---|---|---|---|---|---|
| B0 MFA always | 0.500 | 0.000 | 0.000 | 1.000 | 100.0 | 1.291 | 0 |
| B1 static rules | 0.833 | 0.667 | 0.667 | 0.683 | 3.685 | 1.291 | 0 |
| B2 unbounded AI | 0.801 | 0.673 | 0.680 | 0.683 | 0.352 | 0.047 | 175 |
| PBCA | 0.801 | 0.673 | 0.680 | 0.703 | 4.037 | 1.338 | 0 |

Detection by attack kind:

- **B0 MFA always**: naive 1.000, targeted 1.000, token 1.000
- **B1 static rules**: naive 1.000, targeted 1.000, token 0.050
- **B2 unbounded AI**: naive 1.000, targeted 0.990, token 0.060
- **PBCA**: naive 1.000, targeted 1.000, token 0.110

## RQ1 / RQ2 — session phase

| Setup | ROC-AUC | TPR@1%FPR | TPR@5%FPR | Detected | Step-ups /100 genuine | Restricted genuine % | Looser than d_P |
|---|---|---|---|---|---|---|---|
| B0 MFA always | 0.500 | 0.000 | 0.000 | 0.013 | 1.500 | 0.000 | 0 |
| B1 static rules | 0.500 | 0.000 | 0.000 | 0.013 | 1.500 | 0.000 | 0 |
| B2 unbounded AI | 0.772 | 0.533 | 0.577 | 0.560 | 6.000 | 0.600 | 15 |
| PBCA | 0.772 | 0.533 | 0.577 | 0.560 | 7.500 | 0.600 | 0 |

Detection by attack kind:

- **B0 MFA always**: bulk 0.027, mimicry 0.000
- **B1 static rules**: bulk 0.027, mimicry 0.000
- **B2 unbounded AI**: bulk 1.000, mimicry 0.120
- **PBCA**: bulk 1.000, mimicry 0.120

## RQ2 — property test (random requests, forced-zero risk)

5000 requests: B2 unbounded AI: 2404 decisions looser than d_P, PBCA: 0 decisions looser than d_P

## RQ3 — containment (CAEP vs. waiting for token expiry)

| Misuse | Sessions | Contained before expiry % | Median windows | Trigger→enforcement p95 (ms) | Records exposed (PBCA) | Records exposed (token expiry) |
|---|---|---|---|---|---|---|
| bulk | 34 | 100.0 | 1.000 | 12.2 | 186.4 | 1146.7 |
| mimicry | 37 | 18.9 | 5.000 | 13.0 | 132.7 | 140.7 |

## RQ4 — trade-offs

Decision latency: p50 0.012 ms, p95 12.1 ms

Step-up rate for genuine logins by group:

- frequency:frequent: 3.675% (n=4163)
- frequency:infrequent: 19.4% (n=98)
- role:analyst: 1.745% (n=1089)
- role:it_admin: 21.1% (n=483)
- role:relationship_manager: 2.022% (n=1088)
- role:teller: 1.811% (n=1601)

Threshold sweep (all τ scaled):

| Scale | Login detected | Session detected | Step-ups /100 genuine logins | Flags /100 genuine windows |
|---|---|---|---|---|
| x0.5 | 0.703 | 0.577 | 4.037 | 8.200 |
| x0.75 | 0.703 | 0.567 | 4.037 | 7.900 |
| x1.0 | 0.703 | 0.560 | 4.037 | 7.500 |
| x1.25 | 0.703 | 0.560 | 4.037 | 7.200 |
| x1.5 | 0.703 | 0.557 | 4.037 | 7.100 |

Login-signal ablation (PBCA):

| Signals | ROC-AUC | TPR@5%FPR | Detected | Step-ups /100 genuine |
|---|---|---|---|---|
| all signals | 0.801 | 0.680 | 0.703 | 4.037 |
| no user agent | 0.799 | 0.677 | 0.703 | 4.037 |
| no managed flag | 0.801 | 0.680 | 0.703 | 4.037 |
| IP only | 0.806 | 0.687 | 0.703 | 4.037 |
