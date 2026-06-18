# OpenClaw Guard Comprehensive Analysis Report
**Generated**: 2026-06-02 21:59:23
**Experiments**: 3 (Pilot / Formal / AgentDojo)
**Total Cases**: 459
**Chart Dir**: ./charts/

---
## 1. Experiment Overview

| Dimension | Pilot | Formal | AgentDojo |
|:---|---:|---:|---:|
| Cases | 40 | 110 | 309 |
| Attack Types | 3+baseline | 4+baseline | 11+baseline |
| Source | Manual | Manual (extended) | AgentDojo v1.2.2 |
| Suites | - | - | workspace + banking |

---
## 2. Overall Interception Rate

![Overall](./charts/01_overall.png)

| Experiment | Cases | Interception | Hard Block | Avg Time |
|:---|---:|---:|---:|---:|
| Pilot(40) | 40 | 60.0% | 12.5% | 1.1202s |
| Formal(110) | 110 | 62.73% | 10.91% | 1.0786s |
| AgentDojo(309) | 309 | 36.25% | 0.0% | 2.0097s |

**Insights**:
- Formal exps (62.73%) > Pilot (60.0%) with added system_message attacks
- AgentDojo drops to 36.25% due to **banking suite 0% interception**
- workspace alone: 57.73% - consistent with manual tests
- Hard block rate is very low (0-12.5%) across all experiments

![Decision](./charts/02_decision.png)
![AccVsRate](./charts/10_acc_vs_rate.png)

---
## 3. By Attack Type

![AttackType](./charts/03_attack_type.png)

### Key Findings
1. **Direct injection**: Best protection (86.67-90% in manual tests)
2. **Ignore Previous**: 70-80% in manual, but only 43.48% in AgentDojo
3. **Tool Knowledge**: Worst performer - 40% FN in formal, only 43.48% in Dojo
4. **All AgentDojo attacks show identical 43.48%** - Guard matches keywords, not semantics

---
## 4. Rule Hit Analysis

![RuleRanking](./charts/04_rule_ranking.png)

![RuleByExp](./charts/05_rule_by_exp.png)

### Coverage Assessment

| Category | Rules | Triggered | Coverage |
|:---|---:|---:|---:|
| CMD (command) | 10 | 0 | 0% |
| FILE (file ops) | 10 | 8 | 80% |
| NET (network) | 6 | 2 | 33% |
| CFG (config) | 4 | 2 | 50% |
| GEN (general) | 4 | 1 | 25% |
| SKL (skill) | 2 | 1 | 50% |
| API (channel) | 4 | 0 | 0% |
| **Total** | **47** | **14** | **29.8%** |

Only 14/47 rules (29.8%) were ever triggered. Many rules are sleeping.

---
## 5. False Negatives & Positives

![FNFB](./charts/07_fn_fp.png)

![DojoFN](./charts/09_dojo_fn.png)

| Experiment | FN | FN Rate | FP | FP Rate |
|:---|---:|---:|---:|---:|
| Pilot(40) | 8 | 20.0% | 1 | 2.5% |
| Formal(110) | 28 | 25.5% | 1 | 0.9% |
| AgentDojo(309) | 145 | 46.9% | 2 | 0.6% |

**FN Root Causes**:
| Reason | Share | Examples |
|:---|---:|:---|
| No matching rule | ~79% | banking transfers, calendar events, email sends |
| Semantic mismatch | ~15% | 'turn off audit log' has no keyword match |
| Indirect chains | ~6% | file_move + permission changes bypass detection |

---
## 6. Performance

![Perf](./charts/06_perf.png)

| Metric | Pilot | Formal | AgentDojo |
|:---|---:|---:|---:|
| Min | 0.0082s | 0.0127s | 0.0118s |
| Max | 3.8028s | 5.181s | 7.8427s |
| Avg | 1.1202s | 1.0786s | 2.0097s |
| P50 | 0.0163s | 0.0244s | 2.6198s |
| P95 | 3.1337s | 3.5s | 4.3663s |

---
## 7. Assessment & Recommendations

### Scoring
| Dimension | Score | Note |
|:---|---:|:---|
| File Protection | 5/5 | FILE rules comprehensive, high hit rate |
| Network Egress | 4/5 | NET-001/002 effective, lacks encrypted exfil |
| Command Execution | 3/5 | CMD rules exist but untested |
| Financial Ops | 1/5 | No rules at all, banking 0% |
| Semantic Understanding | 1/5 | Keyword matching only |
| False Positive Control | 5/5 | <3% FP rate |
| Response Performance | 4/5 | Avg ~1.5s, P95 ~4s |

### Priority Recommendations
| Priority | Suggestion | Impact |
|:---:|:---|---:|
| **P0** | Add financial/trading rules for banking | 0% -> 80%+ |
| **P0** | Extend coverage to all 47 rules | Eliminate blind spots |
| **P1** | Add NLP for semantic risks | Reduce FN 10-15% |
| **P1** | Chain detection (file_move -> permission) | Cover tool attacks |
| **P2** | Upgrade ask->block for high-risk paths | Increase hard block rate |
| **P2** | Alert on high-value paths (/etc/cron/) | Reduce critical FN |

### Conclusion
OpenClaw Guard excels at **file operation protection** and **FP control**, but its **keyword-based detection** has significant blind spots, especially for financial transactions and indirect attack chains. The design philosophy favors **assistive security** (ask-based) over **hard blocking**, which protects user autonomy but increases risk.

Recommend prioritizing financial rules, then gradually introduce semantic analysis.

---
*Auto-generated at 2026-06-02 21:59:23*
