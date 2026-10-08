# Cloud Blast-Radius POC: Datasets and Prior Work

**Scope:** Public-cloud security, especially AWS and GCP; Azure where supported.  
**Sources checked:** October 8, 2026.  
**Purpose:** A focused brief of the dataset findings and related work discussed—not an exhaustive literature review or a system design.

## 1. Problem statement

Evaluate whether Prisma-derived cloud inventory, identity and access management (IAM), policies, trust relationships, and relevant workload/network context can support an assumed-breach analysis:

> Given a compromised cloud workload or identity, which identities and sensitive resources could an attacker subsequently access or control, through which permissions or relationships, and which defensive changes would reduce that impact most?

The POC should establish **correctness, scalability, and decision value separately**. Potential reachability is not evidence that a resource was actually compromised.

**Dataset conclusion:** Public test inputs exist, but this review did not verify a ready-to-download, real enterprise-scale AWS/GCP dataset combining complete IAM, network, workload, and independently labeled attack-path information. A practical evaluation will need more than one source.

## 2. Public inputs and their limitations

| Source | What is available | Best use for this POC | Main limitation |
|---|---|---|---|
| **CloudLens research artifacts — AWS** | Public Planning Domain Definition Language (PDDL) model and 19 small attack-planning cases adapted from IAM Vulnerable. [[2]](#ref-2) | Check selected privilege-escalation rules and attack preconditions. | The repository explicitly distinguishes these cases from its real-world data; the latter is still described as awaiting anonymization. Not a public enterprise snapshot. |
| **IAMAX — abstract cloud-IAM graphs** | Repository lists `data/synthetic_graphs.zip`, experiment code, and a synthetic-data generator. [[4]](#ref-4) | Permission-exposure experiments and evaluating access-policy changes. | Graph-level research inputs, not a complete multi-cloud inventory or fully labeled end-to-end attack-path benchmark. |
| **CloudGoat — AWS and Azure** | Vulnerable deployment scenarios, infrastructure definitions, and walkthroughs. The current README documents both clouds. [[5]](#ref-5) | Build small, understandable tests with documented attack routes. | A deployable lab, not a pre-exported enterprise dataset. Walkthroughs are not exhaustive labels for every possible path. |
| **TerraGoat — AWS, GCP, and Azure** | Public Terraform configurations with intentional misconfigurations. [[6]](#ref-6) | Test configuration ingestion and resource-relationship extraction. | A training/configuration repository, not an enterprise-scale graph with verified attack-path ground truth. |

**Usage notes:** CloudGoat lists BSD-3-Clause; TerraGoat lists Apache-2.0. No explicit code/data license was verified for the CloudLens or IAMAX artifacts reviewed; obtain clarification before organizational reuse. [[2]](#ref-2) [[4]](#ref-4) [[5]](#ref-5) [[6]](#ref-6) Vulnerable labs belong only in isolated, authorized environments—not production. Dataset archives and tools were not executed for this brief.

## 3. What other researchers and tool authors did

### CloudLens: reason about multi-step changes to permissions

**Mikhail Kazdagli, Mohit Tiwari, and Akshat Kumar; 2024 arXiv preprint.** CloudLens represents permissions as relations and uses automated planning to find attack sequences, including actions that change access rights. The authors evaluated **14 commercial AWS configurations**. [[1]](#ref-1)

Their Table 2 reports the following for **dataset 13**:

| Component | Reported count |
|---|---:|
| Users | 582 |
| Groups | 110 |
| Roles | 64,880 |
| Datastores | 2,857 |
| Permissions | 12,150,172 |

These are author-reported configuration statistics, **not 12 million cloud resources**. To manage scale, the authors partitioned by account and, when necessary, by user subsets plus reachable entities. Planner translation remained a time/memory bottleneck. They detected all **19 modeled scenarios out of 31** in IAM Vulnerable; 12 were outside the implemented scope. [[1]](#ref-1)

**POC implication:** Model how a compromise can create new privileges, not only traverse existing access. Treat the scale figures as evidence of a relevant research workload—not proof of complete, unpartitioned organization-wide analysis. The authors are a concrete lead for requesting anonymized data; access is not guaranteed. [[2]](#ref-2)

### IAMAX: reduce compromise impact by optimizing permissions

**Same authors; IJCAI-ECAI 2022, peer-reviewed main-track paper.** This older work is included because it provides relevant public artifacts. It combines constraint programming with graph representation learning to reduce unused permissions while preserving observed accesses and forming interpretable access groups. It evaluates the impact of compromising one to three users. [[3]](#ref-3)

The paper uses **eight real organizational datasets and 280 synthetic graphs**. Synthetic instances sample **10–150 users and 50–300 datastores**. Generation uses real graphs as baselines, retaining density characteristics and ensuring observed-access edges remain a subset of permission edges. [[3]](#ref-3)

For optimization, the authors use constraint programming rather than a much larger linearized formulation, with a **15-minute solver limit** on **96 vCPUs and 192 GB RAM**. That is an experimental budget, not a guaranteed runtime for every input. [[3]](#ref-3)

**POC implication:** Evaluate whether recommended permission changes reduce reachable sensitive data—not merely whether the dashboard displays paths. IAMAX is useful for small exposure/optimization experiments, not proof of enterprise-scale attack-path performance.

### Principal Mapper (PMapper): an existing AWS comparison baseline

**NCC Group and Erik Steringer; open-source tool.** PMapper models AWS users and roles as a directed graph. Its queries combine local authorization simulation with indirect access through other principals, helping identify privilege escalation and alternate routes to actions/resources. It lists an AGPL-3.0 license. [[7]](#ref-7)

**POC implication:** Compare results on overlapping AWS scenarios. Investigate disagreements rather than assuming either tool is a correctness oracle. PMapper is a tool, not a downloadable enterprise dataset; its existence also means basic IAM graph visualization alone is not a novel contribution.

## 4. How to test whether the POC works at scale

The following is a **proposed evaluation approach**, not a published dataset or measured result.

| Evaluation layer | Suggested inputs | What it can establish |
|---|---|---|
| **Correctness** | Reviewed CloudLens/CloudGoat cases, plus deliberately blocked variants | Whether supported attack rules, preconditions, and reachable-target results are correct. |
| **Realism** | A small approved Prisma configuration export, supplemented where necessary | Whether the analysis handles actual policy structures, ownership, and relationships. Alert summaries alone should not be assumed sufficient. |
| **Scalability** | Offline, interconnected synthetic cloud configurations | Runtime, memory, and update behavior under explicitly documented workloads. |

### Proposed stress-test sizes

| Test | Identity/resource nodes | Modeled relationships |
|---|---:|---:|
| Initial | 10,000 | 100,000 |
| Larger | 100,000 | 1 million |
| Enterprise-scale stress | 1 million | 10 million |

Do not deploy these quantities of live resources just to create a benchmark. Generate offline inputs, and report configuration facts separately from derived attack edges: one permission record is not automatically one exploitable relationship.

For meaningful tests, include cross-account links, shared privileged roles, branching routes, cycles, and blocked paths—not just disconnected copies of a small lab. Generate **configuration inputs**, allowing the POC to infer access. AWS evaluation must account for applicable policies and controls, including explicit denies, permissions boundaries, and organization policies. [[8]](#ref-8) A GCP extension needs independently checked GCP-specific semantics; AWS tests do not validate it.

Keep expected answers independent of the POC. Planted attack paths test whether those paths are found; they do not establish that every unplanted result is false. Test full reachable-target sets in small cases where those sets can be verified.

**Measure:** precision/recall for supported cases; false and missed reachable targets; policy-evaluation and graph-build time; single-start and many-start blast-radius latency; peak memory; update/recomputation time; and reachable sensitive resources before/after a proposed remediation. Document excluded rules and unknown relationships alongside results.

## 5. Recommended next step and value hypothesis

Start with reviewed small scenarios, use IAMAX for adjacent permission-impact experiments, and build an offline synthetic corpus for scale. In parallel, request CloudLens research-data access and seek approval for a representative Prisma export.

The proposed enterprise value is **better incident scoping and remediation prioritization**, not a larger graph display. Demonstrate whether analysts identify the affected business-critical resources faster and whether a recommended change removes validated exposure without breaking required access. No ROI or production-accuracy claim is established by these sources for this POC.

**Bottom line:** Public material can support an initial proof of correctness. Synthetic data can support performance claims under stated assumptions. Representative real data and independent validation are still needed to demonstrate production accuracy and organizational value.

## References

<a id="ref-1"></a>
**[1]** Mikhail Kazdagli, Mohit Tiwari, and Akshat Kumar. *CloudLens: Modeling and Detecting Cloud Security Vulnerabilities*. arXiv:2402.10985, 2024; version 4, December 24, 2024. See Sections 3–5 and Appendix B, Table 2 (PDF page 10). [Paper](https://arxiv.org/abs/2402.10985v4) · [PDF](https://arxiv.org/pdf/2402.10985v4).

<a id="ref-2"></a>
**[2]** CloudLens author repository. Public model/test cases and the “Real-World Datasets” availability statement. [Repository](https://github.com/mikhail247/cloudlens).

<a id="ref-3"></a>
**[3]** Mikhail Kazdagli, Mohit Tiwari, and Akshat Kumar. *Using Constraint Programming and Graph Representation Learning for Generating Interpretable Cloud Security Policies*. Proceedings of IJCAI-22, main track, pp. 1850–1858, 2022. DOI: 10.24963/ijcai.2022/257. See Sections 6–7; dataset generation and computational setup are on p. 1856. [Publication](https://www.ijcai.org/proceedings/2022/257) · [PDF](https://www.ijcai.org/proceedings/2022/0257.pdf).

<a id="ref-4"></a>
**[4]** IAMAX supplemental repository. [Code and instructions](https://github.com/mikhail247/IAMAX) · [Data folder containing `synthetic_graphs.zip`](https://github.com/mikhail247/IAMAX/tree/main/data) · [Archive file page](https://github.com/mikhail247/IAMAX/blob/main/data/synthetic_graphs.zip).

<a id="ref-5"></a>
**[5]** Rhino Security Labs and CloudGoat contributors. *CloudGoat*. Scenario descriptions, supported-cloud setup, safety warnings, and license. [Repository](https://github.com/RhinoSecurityLabs/cloudgoat).

<a id="ref-6"></a>
**[6]** Bridgecrew and contributors. *TerraGoat: Vulnerable Terraform Infrastructure*. AWS/GCP/Azure configuration examples and license. [Repository](https://github.com/bridgecrewio/terragoat).

<a id="ref-7"></a>
**[7]** NCC Group and Erik Steringer. *Principal Mapper (PMapper)*. README description of graph-based IAM analysis and authorization simulation. [Repository](https://github.com/nccgroup/PMapper).

<a id="ref-8"></a>
**[8]** Amazon Web Services. *Policy evaluation logic — AWS Identity and Access Management*. [Official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).
