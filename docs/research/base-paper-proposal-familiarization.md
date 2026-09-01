# Base paper and H2 proposal familiarization

## Sources and scope

This note synthesizes the local primary sources in preparation for smoke tests and a full experiment:

- `Adaptive Hybrid Insider Threat Detection with Machine Learning and Explainable AI.pdf` (Namsey et al., 2026; hereafter **P2**), cited by PDF page, section, figure, or table.
- `H2-Proposal-Does-the-Model-Beat-the-Rules.docx` (hereafter **H2 proposal**), cited by numbered section and named item.
- `Thesis Adaptive Hybrid Insider Threat Detection with Machine Learning and Explainable AI.docx` (hereafter **hypothesis-development document**), cited by step/subsection. This is the broader precursor that selects H2 as the strongest candidate; the H2 proposal is the more specific design authority where they differ.

## Study claim, questions, and hypotheses

P2 claims that an adaptive Isolation Forest, retrained monthly with verified false positives, reduces false positives by 33.17% without reducing recall, and that hybrid model/rule re-ranking raises top-1% precision from 38.89% to 100% (P2, pp. 3–6, §§III.E–F and IV.B–C, Tables V–VI). P2 does **not** report rules-only ranking, uncertainty, a weight sweep, or multiple random seeds (H2 proposal, §§1–2).

The proposed praxis asks whether the learned anomaly score adds operational triage value beyond a strong deterministic-rule baseline. Its primary hypothesis is that pool-conditional hybrid precision@5% exceeds tuned rules-only precision by more than 5 percentage points and remains advantageous for anomaly weight `w` from 0.3 through 0.9 (H2 proposal, §4, “H2 · PRIMARY”). The proposal decomposes this into:

- **RQ0 / reproduction:** reproduce P2 and measure sensitivity to seed, unpublished rule weights, and ties.
- **RQ1 / H2.1:** hybrid versus rules-only ranking on the *same Isolation-Forest-selected pool*.
- **RQ2 / H2.2:** full adaptive pipeline versus a standalone rules detector/ranker at equal alert budgets.
- **RQ3 / H2.3:** sweep `w = 0.00, 0.05, …, 1.00`; test whether any gain survives outside rule-dominant settings.
- **RQ4 / H2.4:** remove `wikileaks_flag` from both relevant rankers and estimate the difference in precision degradation.
- **RQ5 / H2.5:** test whether the sign of the result replicates for CERT r4.2 scenarios 2 (IP theft) and 3 (sabotage) using scenario-specific rules.

These mappings and their explicit disconfirmation conditions appear in H2 proposal §§3–4. The broader hypothesis-development document independently identifies H2 as the strongest candidate because a rules-only match is plausible and decision-relevant (Step 3, “H2 — KEEP”).

## Data, preprocessing, and original pipeline

P2 uses CERT r4.2, narrowed to data-leakage scenario 1. It reports 960 retained users, 30 malicious users, 85 malicious user-days, 321,514 normal user-days, 59 extracted features, and 34 modeling features; users ever associated with scenarios 2 or 3 are removed (P2, p. 3, §III.A and Table I). Raw `logon.csv`, `http.csv`, and `device.csv` events are aggregated to user-day records (P2, p. 3, §III.A).

Features include logon/PC/off-hour/session/web/domain/USB aggregates and binary flags such as `wikileaks_flag` and `offhour_usb_flag`; `afterhours_usb_connects` is also named as a scenario-tailored indicator (P2, p. 3, §§III.B–C). Modeling inputs are per-user z-scores computed from past-only expanding and seven-day rolling means/standard deviations (P2, p. 3, §III.C). The temporal split is June 30, 2010: activity on or before that date is training, later activity is test, and only benign training rows fit the anomaly detector (P2, p. 3, §III.D).

The selected detector is Isolation Forest with per-user standardization and per-user thresholds at the 99th percentile of benign training scores (P2, pp. 3–5, §§III.E and IV.A, Tables II–IV). In “Expand FP-only,” the model scores one test month, adds that month’s verified false-positive alerts to training, retrains, and proceeds to the next month (P2, p. 3, §III.E). Monthly alerts are ranked by

`hybrid_score = w × anomaly_norm + (1 − w) × rule_norm`,

where both components are normalized to `[0,1]`; P2 describes anomaly normalization using extrema from the “current training pool” and uses `w = 0.7` in its reported comparison (P2, p. 4, §III.F.1, Eq. 1 and Fig. 3; P2, pp. 5–6, §IV.C and Table VI; H2 proposal, §§1 and 5).

## Comparators and endpoints in the proposed experiment

The proposed rankers are random ordering (R0), pool-conditional rules-only (R1), anomaly-only (R2), P2 hybrid at `w=0.7` (R3), swept hybrid (R4), standalone rules detector/ranker (R5), and oracle ordering (R6). R1 and R5 also receive a no-`wikileaks_flag` ablation (H2 proposal, §5).

The primary endpoint is pool-conditional **difference in precision@5%**, i.e. the top 92 of P2’s 1,842 adaptive alerts. The queue size is reconstructed as 1,763 false positives plus 79 true positives (P2, Table V; H2 proposal, opening summary and source note). Precision@1% (18 alerts) is retained as reproduction-only; precision@2% and @10%, precision at absolute budgets, recall@budget over all 85 malicious days, PR-AUC, mean average precision, tie mass, seed dispersion, and ROC-AUC for continuity are secondary or diagnostic (H2 proposal, §6). P2’s anchors are 79/85 recall, 1,763 adaptive false positives, and hybrid/model precision of 100/38.89%, 94.44/41.67%, 70.65/41.30%, and 37.50/27.72% at the top 1%, 2%, 5%, and 10%, respectively (P2, pp. 5–6, Tables V–VI).

The full analysis proposes 30 Isolation-Forest seeds, a paired user-cluster bootstrap over 960 users with 10,000 BCa replicates, 1,000 random permutations within tied-score groups plus best/worst tie bounds, TOST equivalence against ±5 percentage points, and Benjamini–Hochberg correction for secondary bands and scenario replication (H2 proposal, §7).

## Assumptions that should become explicit test fixtures

1. A “malicious day” is the positive unit, while users are the resampling cluster and alert budgets count user-day rows (P2, p. 3, Table I; H2 proposal, §§6–7).
2. The model-selected pool for RQ1 is exactly the 1,842 alerts produced by Expand-FP-only, not all scored test rows (H2 proposal, §§1–2 and §5, R1).
3. Feedback is an oracle simulation: all and only known false-positive alerts are added after each month; no label delay or analyst error is modeled (P2, p. 3, §III.E).
4. Rule weights are tuned using training data only, and the test partition remains untouched until the rules, tie policy, endpoints, and preregistration are locked (H2 proposal, §§2, 7, 10 phase 02).
5. `w` weights the anomaly component, so `w=0` is rules-only and `w=1` anomaly-only (P2, p. 4, Eq. 1; H2 proposal, §5).
6. The 5-point practical-equivalence margin and 5% primary band are fixed before test analysis (H2 proposal, §§4, 6, and 11).

## Reproducibility and validity risks to resolve before full experiments

### Blocking implementation ambiguities

- **No executable artifact or complete feature schema is present.** P2 names examples but not all 34 modeling features or their exact aggregation/missing-value/zero-variance rules (P2, p. 3, §§III.A–C and Table I).
- **Isolation-Forest configuration is incomplete.** P2 does not state library/version, estimator count, contamination, sampling, random seed, or other hyperparameters; these can change the alert pool and every downstream result (P2, pp. 3–5, §§III.E and IV.A).
- **Rule construction is under-specified.** P2 gives example flags but neither complete predicates nor weights (P2, pp. 3–4, §§III.B–C and III.F.1). The proposal’s training-only grid search is sensible, but the grid, objective, tie-breaker, and whether weights can be zero must be preregistered (H2 proposal, §§2 and 11).
- **Score calibration needs a precise formula.** “Dynamic” min–max normalization from the current training pool is ambiguous about whether extrema are recomputed monthly, which rows supply rule extrema, how out-of-range test scores are clipped, and what happens when max equals min (P2, p. 4, §III.F.1).
- **Threshold evolution is unclear.** P2 specifies initial per-user 99th-percentile thresholds but not whether thresholds are recomputed after each expanded refit, nor what happens for users with sparse/no benign history (P2, pp. 3–4, §III.E and Fig. 2).
- **R5 lacks a candidate-generation definition.** A standalone rule ranker needs an explicit eligibility universe, zero-score policy, alert threshold, and matched-budget selection rule; otherwise “rules select their own pool” is not reproducible (H2 proposal, §§2, 5, and RQ2).
- **Scenario replication invites researcher degrees of freedom.** “Scenario-appropriate” rule sets for scenarios 2 and 3 need a fixed derivation procedure independent of test labels; otherwise RQ5 can tune rules to scripted outcomes (H2 proposal, §§3–5 and §10 phase 05).

### Statistical and construct risks

- P2’s top-1% result contains only 18 alerts and has no uncertainty; moving primary inference to 92 alerts is justified, but it changes the headline estimand and must remain visibly paired with the 1% reproduction result (P2, p. 6, Table VI; H2 proposal, §§6 and 11).
- Binary rules create large ties. Expected random-tie precision is appropriate, but the randomization must be nested consistently inside seeds/bootstrap samples and use recorded RNG streams (H2 proposal, §§6–7).
- There are only 30 malicious users. User-cluster resamples may contain few or no positives, and BCa intervals can be unstable; the protocol needs defined handling and a simulation/power check for the ±5-point equivalence claim (P2, p. 3, Table I; H2 proposal, §7).
- The primary wording requires advantage across an interval of `w`, while the inferential endpoint is stated at precision@5% and H2.3 adds pointwise confidence intervals. A single preregistered decision rule is needed for “holds across,” including multiplicity treatment and whether endpoints at `w=0` or near zero are logically eligible (H2 proposal, §§4 and 7).
- The margin rationale says 5 points is about 4.6 alerts but describes that count as *below* the level that would reprioritize a queue. This does not clearly justify 5 points as the minimum important difference; committee/SOC justification is still an open decision (H2 proposal, §§4 and 11).
- Pool-conditional RQ1 cannot establish that ML is needed for detection because Isolation Forest already selected the pool. RQ2 is therefore necessary, and conclusions must keep the two estimands separate (H2 proposal, §2 and §§3–4, RQ1/RQ2).
- `wikileaks_flag` is tailored to the scripted exfiltration scenario and may approximate the label. The ablation diagnoses benchmark signature dependence, but neither a hybrid win nor rules win on synthetic CERT data establishes real-SOC effectiveness (P2, p. 3, §III.B; H2 proposal, §§1, 4 H2.4, and 8).
- P2’s SHAP and generative-summary components are qualitative and under-specified, but they are not needed to answer H2. Smoke tests should avoid rebuilding them unless reproduction scope explicitly includes non-H2 pipeline outputs (P2, pp. 4–6, §§III.F.2 and IV.D; hypothesis-development document, Step 2, H3–H4).

## Readiness conclusion

The proposal has a defensible core: reproduce P2, compare hybrid and tuned rules on the same pool, then repeat end-to-end at matched budgets, with weight robustness and signature ablation. Smoke tests should first validate data counts, temporal leakage barriers, feature determinism, monthly feedback chronology, score direction/normalization, threshold behavior, ranker endpoint identities (`w=0` and `w=1`), tie invariance, and exact reproduction arithmetic. The full experiment should not begin until the blocking ambiguities above are converted into a versioned protocol/configuration.
