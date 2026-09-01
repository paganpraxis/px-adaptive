# H2 executable experiment protocol

Protocol version: 1.0. The machine-readable authority is `configs/full.json`; any amendment requires a new version and must be made before examining test-partition outcomes.

## Reconstruction assumptions

P2 does not publish executable code, all 34 feature definitions, Isolation Forest hyperparameters, rule weights, or all threshold/normalization details. This implementation therefore fixes the following reconstruction rather than claiming bit-for-bit replication:

| Ambiguity | Fixed reconstruction |
|---|---|
| Event time | CERT timestamps parsed as `%m/%d/%Y %H:%M:%S`; business hours are 08:00–17:59 inclusive. |
| Session duration | First-to-last log event span per user-day; reported separately as a reconstruction limitation. |
| Baselines | Past-only expanding and seven-observation rolling statistics, shifted one row; zero/undefined SD becomes 1; z-scores clipped to ±20. |
| IF | scikit-learn IsolationForest, 200 trees, `max_samples=auto`, `contamination=auto`; anomaly is negative `score_samples`. |
| Threshold | Per-user 99th percentile recomputed after each monthly FP-only expansion; unseen users use the current global 99th percentile. Alerting uses `score > threshold`. |
| Normalization | Monthly test scores use current training-score extrema, clip to [0,1], and map a zero-range component to 0. |
| Rule definitions | WikiLeaks URL substring; off-hour USB connection indicator; off-hour USB connection count. Predicates are fixed before tuning. |
| Rule weights | The original P2-period descriptive analysis uses equal weights plus the full sensitivity surface. Confirmatory weights use grid `{0,1,2,4}³` excluding all-zero, optimized by average precision in an early post-split calibration window only. Lowest L1 norm then lexicographic order breaks ties. |
| Percent budgets | `floor(pool_size × percent / 100)`, minimum 1; this yields 18/36/92/184 for P2's 1,842 alerts. |
| Feedback | Oracle labels; false positives from month M enter training only before scoring month M+1. |

All 85 scenario-1 positives occur after P2's June 30 cutoff, so supervised rule tuning on P2's detector-training partition is impossible. The detector split remains unchanged. The first whole-day block containing at least 30% of scenario-1 malicious user-days is used for rule calibration; only strictly later days support confirmatory tuned-rule inference. No rows are moved to equalize class ratios. Full-period equal-weight and weight-sensitivity results remain descriptive and directly aligned with P2's evaluation period.

For r4.2 scenario 1, this rule places July 1–August 12, 2010 in calibration (26 malicious user-days) and all dates after August 12 in the confirmatory holdout (59 malicious user-days; first holdout positive September 10). The realized calibration share is 30.59%; whole days are never split to force exactly 30%.

## Comparator matrix

| ID | Score and ordering | Candidate pool | Purpose |
|---|---|---|---|
| R0 | Uniform random order; expectation equals pool prevalence | Same pool as the paired comparator | Random floor |
| R1 | Tuned normalized rule score; `w=0` | Expand-FP-only IF alert pool | RQ1 rules-only comparator |
| R2 | Normalized anomaly score; `w=1` | Same IF alert pool | P2 model-only comparator |
| R3 | `0.7 anomaly + 0.3 rules` | Same IF alert pool | P2 hybrid reconstruction |
| R4 | `w anomaly + (1-w) rules`, `w=0,.05,…,1` | Same IF alert pool | RQ3 sweep |
| R5 | Tuned normalized rule score | All eligible post-split user-days, selecting the top matched budget | RQ2 standalone rules |
| R6 | Malicious rows first, uniform inside label groups | Same pool as paired comparator | Oracle ceiling |

For RQ2, the full pipeline selects its IF-alert pool and ranks it by hybrid score. R5 ranks every post-split user-day. Both return exactly `k` rows for each matched absolute budget. Zero-rule-score rows remain eligible so every system can meet the same budget. Expected random ordering resolves boundary ties.

## Endpoints

| Status | Endpoint | Operational definition | RQ |
|---|---|---|---|
| Primary | Δ precision@5% | Expected top-92 precision on the same 1,842-alert pool: hybrid minus R1 | RQ1/H2 |
| Co-primary | Δ recall@matched budget | Difference in distinct malicious user-days retrieved at `k={18,36,92,184}` from each architecture's own eligible pool | RQ2 |
| Reproduction | Recall, FP count, pool size, precision@1/2/5/10% | P2 split, scenario 1, reconstructed adaptive pool | RQ0 |
| Secondary | Precision@1/2/10%, precision@10/25/50/100, PR-AUC | Same-pool paired comparisons; PR-AUC is average precision over the ranked pool | RQ1/RQ3/RQ4 |
| Secondary | Scenario-local Δ precision@5% | Hybrid minus rerun rules comparator within each scenario; never compared directly with scenario-1 P2 numbers | RQ5 |
| Diagnostic | Tie mass/bounds, seed SD, alert counts, threshold fallback count | No hypothesis decision from these alone | RQ0–RQ4 |

The 1% band contains only 18 alerts and remains a prominent reproduction endpoint. It is not used for primary inference; 5% (92 alerts under the P2 anchor pool) is the prespecified actionable band.

## Statistical plan

- Resample users, not user-days, because observations within an employee are dependent. Preserve all sampled rows and sample user clusters with replacement.
- Compute both rankers on each identical resample and bootstrap their difference, not two independent intervals.
- Use 10,000-replicate BCa 95% intervals. Define and report resamples containing no positive rows; they contribute recall 0 only when the estimand is defined, otherwise they are invalid and their frequency is reported.
- Repeat the detector over the 30 fixed seeds in configuration. Report the seed mean, SD, range, and the seed-by-bootstrap uncertainty separately.
- Test practical equivalence with paired TOST against `[-0.05,+0.05]`; “not significant” never implies equivalence.
- The primary comparison is unadjusted. Apply Benjamini–Hochberg at q=.05 to secondary bands and the scenario family.
- The interval-wide H2 claim is an intersection-union test: hybrid must exceed +.05 at every prespecified `w` from .30 through .90 using multiplicity-adjusted lower bounds. The complete sweep is descriptive; its test-set maximum is not a tuned production weight.

## Tie policy

For every equal-score group intersecting a budget boundary, report expected precision under uniform random ordering and the attainable best/worst bounds. The implementation computes the expectation analytically; any permutation audit uses recorded RNG streams. If the substantive verdict changes across bounds, classify it as tie-indeterminate. Pair rankers on the same sampled users, but do not force common tie ordering across different score partitions.

## Sweep and ablation grid

| Dimension | Grid |
|---|---|
| Hybrid weight | `0,.05,…,1`; confirmatory interval `.30,.35,…,.90`; P2 point `.70` |
| Flag set | Full; no `wikileaks_flag`; `wikileaks_flag` alone |
| Detector seed | 30 fixed integers in `configs/full.json` |
| Scenario | r4.2 scenario 1 confirmatory; scenarios 2 and 3 replication only |
| Percent budget | 1%, 2%, 5%, 10% |
| Absolute budget | 10, 18, 25, 36, 50, 92, 100, 184 |

Scenario 2/3 rule predicates must be recorded in a new scenario configuration using scenario documentation and pre-cutoff data only. Their raw results receive scenario-local baselines; they are not numerically juxtaposed with P2 anchors.

## Preregistration lock

Before reading confirmatory holdout metrics, freeze and hash: raw-data provenance; exclusion list; label conversion; event predicates; feature list/formulas; missing/zero-variance rules; split inclusivity; calibration fraction and whole-day boundary rule; model library/version/hyperparameters; seed list; threshold refresh/fallback; score direction/normalization/clipping; feedback timing; rule grid/objective/tie-break; every candidate universe; zero-score eligibility; budgets/rounding; endpoints; δ=.05; bootstrap/BCa rules; invalid-resample handling; multiplicity family; weight decision rule; tie policy; ablations; stopping/reproduction-gap rules; and output schemas.

## Threats and built-in mitigation

| Threat | Mitigation |
|---|---|
| Weak rules manufacture a hybrid win | Fixed predicates and training-only weight grid; publish selected weights and full grid surface. |
| Inference on 18 alerts | 5% primary; 1% reproduction only; report tie bounds and intervals. |
| Correlated user-days | User-cluster resampling with paired differences. |
| “No significance” treated as equivalence | Paired TOST with fixed ±5-point margin. |
| Model-conditioned pool favors model | Separate RQ2 using all post-split user-days and matched budgets. |
| Stochastic single-seed result | Thirty fixed seeds and seed-dispersion output. |
| Scenario-encoding WikiLeaks flag | Removal and flag-alone ablations; restrict claims to synthetic CERT. |
| Researcher-designed scenario 2/3 rules | Independent derivation protocol frozen before scenario outcomes. |
| Under-specified P2 implementation | Versioned assumptions plus sensitivity analysis and explicit reproduction-gap report. |
| Test-set optimum overstates performance | Full sweep labeled descriptive; only prespecified points/range are confirmatory. |

## Execution phases and artifacts

| Phase | Command / action | Required artifact |
|---|---|---|
| 0 | Validate standardized `labels.csv` and raw file schemas | Data manifest, hashes, count audit |
| 1 | `python -m pxadaptive smoke --config configs/smoke.json --output runs/smoke` | Passing manifest and fixture metrics |
| 2 | Run scenario-1 reconstruction | Feature dictionary, per-seed reproduction table, reproduction-gap report |
| 3 | Freeze the first-30%-positive whole-day calibration boundary, tune rules there, and lock registration before viewing later outcomes | Boundary audit, weight-grid results, selected weights, config hash |
| 4 | Run RQ1/RQ2 over 30 seeds | Tidy ranker metrics and matched-budget results |
| 5 | Run w sweep and WikiLeaks ablations | Robustness surface, difference-in-differences table |
| 6 | Run clustered inference | BCa intervals, TOST, adjusted secondary p-values, tie audit |
| 7 | Repeat with frozen scenario-local configs | Scenario 2/3 local-baseline results and sign-replication table |

## Input contract and commands

The data directory must contain `logon.csv`, `http.csv`, `device.csv`, and a derived `labels.csv` with columns `user,date,scenario`. The label conversion from the distributed CERT answer key must be separately versioned and hashed.

```bash
python -m pip install -e '.[test]'
python -m unittest discover -v
python -m pxadaptive smoke --config configs/smoke.json --output runs/smoke
python -m pxadaptive run --config configs/full.json --data /path/to/cert-r4.2 --output runs/r4.2-s1
```
