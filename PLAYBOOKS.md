# Cortex Cloud Remediation Playbooks — Architecture & Continuation Guide

This document exists so a future session (human or AI agent) can pick up this work without
re-deriving the design. It covers the architecture, the naming/tagging convention, the exact rule
inventory, the asset-field conventions, the gotchas hit so far, the known open items, and
step-by-step instructions for extending it (new rules, new categories, migrating AWS, adding GCP).

Read this before touching any `.yml` file in this repo. Last updated after the Azure v2 rewrite,
the naming convention and the tagging pass.

## 0. Status snapshot

| Area | State |
|---|---|
| Hub (cloud router) | Done. `[GR][All][Dispatch] Cloud provider` |
| Azure (dispatch + Network/Compute/Identity/Data) | **v2 model, done** (in `azure-remediation/`) |
| AWS (dispatch + Network/Compute/Identity/Data) | **v2 model** (migrated from v1 in the same way as Azure; in `aws-remediation/`). **Not yet imported or tested in Cortex** |
| GCP (dispatch + Network/Compute/Data; no Identity rules) | **v2 model, built** (in `gcp-remediation/`), hub routed. **Not yet imported or tested in Cortex; the fields of all 5 asset types (firewall, subnet, GKE cluster, bucket, VM) are verified against real assets; the only thing left unverified is whether `gcp-container-cluster-security-update` accepts a *zone* in its `region` argument (checked only in the docs of a sibling command)** (§7, §9) |
| Naming convention + tags | Applied to all 15 playbooks (the helper keeps `[helper]`) |

"v1 model" = fan-out title → per-rule gate → action → hardcoded manual step, using
`Core.CoreAsset.[0]` from a shared context (`separatecontext: false`). "v2 model" = see §2–§3.
The v1 model **did not work in Cortex for Azure** (the user fixed it by hand, which produced v2).
AWS was then migrated to v2 by applying the same changes (§10.4); the old v1 AWS files exist only as
a backup outside the repo.

## 1. Repository layout

```
playbook/
  PLAYBOOKS.md                                    this file
  [GR][All][Dispatch]_Cloud_provider.yml          Level 1 hub (cloud provider router)
  [helper]_get-asset-details.yml                  shared helper sub-playbook (user-authored, tag: helper)
  azure-remediation/                              Azure playbooks (v2 model)
    [GR][Azure][Dispatch]_Misconfiguration.yml
    [GR][Azure][Remediation]_Network.yml
    [GR][Azure][Remediation]_Compute.yml
    [GR][Azure][Remediation]_Identity.yml
    [GR][Azure][Remediation]_Data.yml
  aws-remediation/                                AWS playbooks (v2 model, same pattern as Azure)
    [GR][AWS][Dispatch]_Misconfiguration.yml
    [GR][AWS][Remediation]_Network.yml / _Compute.yml / _Identity.yml / _Data.yml
  gcp-remediation/                                GCP playbooks (v2 model): Dispatch + Network / Compute / Data
```

Each `.yml` is an independent Cortex playbook, imported/updated by its own top-level `id:`.
**Never change an existing playbook's `id:`** — Cortex uses it to decide "update in place" vs
"create a new playbook". Renaming the file or the `name:` is fine; changing `id:` is not.

There is **no git repo**. Before any bulk edit, copy the files somewhere safe first.

## 2. Architecture (3 levels)

```
Cortex Cloud issue (issue.cloudprovider, issue.ruleid, issue.asset_ids)
        |
        v
[L1] [GR][All][Dispatch] Cloud provider         [GR][All][Dispatch]_Cloud_provider.yml
        start -> [helper] get-asset-details -> single condition "Choose playbook to run" on the
        asset's provider: asset_data.xdm__asset__provider == AWS / AZURE / GCP:
        AWS -> AWS dispatch | Azure (matches the string "AZURE") -> Azure dispatch |
        GCP -> GCP dispatch | #default# -> Done
        calls the L2 playbook with separatecontext: true, ruleId = ${issue.ruleid}; #error#/#none# -> Done
        (the helper has no #default#/#error# here: an issue that doesn't have exactly one asset
        stops in the hub without reaching Done)
        |
        v
[L2] [GR][<Cloud>][Dispatch] Misconfiguration
        start -> ONE condition "Evaluate triggered rule" with 4 labels -> one sub-playbook call per
        label (separatecontext: true, no arguments: each L3 defaults ruleId to ${issue.ruleid}) -> Done.
        No #default#, no #error#. Label sizes: Azure Network 23 ids / Compute 9 / Identity 1 / Data 9;
        AWS Network 5 / Compute 6 / Identity 2 / Data 10. AWS is built exactly like Azure.
        |
        v
[L3] [GR][<Cloud>][Remediation] <Category>       (Network | Compute | Identity | Data)
        (Azure and AWS alike) start -> [helper] get-asset-details -> ONE condition "Evaluate triggered rule"
        (one label per rule or per group of rules that share the same action) -> action task.
        Action success -> "Set issue as fixed" -> Done.
        Action failure (#error#) -> "get Issue Recommendations" -> "Manually update asset"
        (description = ${Core.IssueRecommendations.Description}) -> Done.
```

Design decisions that were made with the user (don't reverse without asking):
- Category playbooks are separate files so each canvas stays small.
- **Each playbook has a single central condition task** that evaluates `inputs.ruleId` (labels =
  human names of the rule/group), *not* a fan-out of per-rule gates. (An earlier flat design used
  fan-out + per-rule gates; the user moved back to the central switch once categories became small.)
- Rules that share the exact same action share one label + one action task (e.g. the 3 "HTTPS
  redirect" rules in Azure Compute, the 3 "storage public access" rules in Azure Data).
- The dispatch levels only call other playbooks; only `Remediation` playbooks run cloud commands.
- Switch conditions have **no `#default#`**: an unmatched rule silently ends that branch.

## 3. The v2 pattern in detail

**`[helper] get-asset-details`** (tag `helper`, `id 9a7dd5de-…`): checks the issue has exactly one
asset (`issue.asset_ids` deduplicated count == 1; otherwise it stops silently), finds it in
`Core.CoreAsset` (`asset_index`), runs `core-get-asset-details` on `${issue.asset_ids}` if not
loaded, and exports two outputs to the caller: `asset_index` and **`asset_data` (= the whole
`${Core.CoreAsset}` list)**. Every v2 L3 playbook calls it first, with `separatecontext: true`, so its
outputs land in the caller's context. Downstream tasks reference the context key `asset_data`
(not an input), e.g. `${asset_data.xdm__asset__raw_fields.Platform Discovery.name}`.

**Why `separatecontext: true` everywhere in v2:** the original design relied on `separatecontext:
false` so `Core.CoreAsset` resolved in L2 would be visible in L3. The user reported the Azure playbooks
did not work and rebuilt them with isolated contexts, each L3 resolving its own `asset_data` via the
helper. The exact root cause was not diagnosed (the shared-context assumption is the likely suspect).

**`ruleId` input:** every L3 (and L2) declares `ruleId` with default `${issue.ruleid}`. The switch
reads `inputs.ruleId`. The hub passes `ruleId` to the dispatch; the Azure dispatch passes nothing to the
L3 playbooks and relies on that default. A sub-playbook whose `ruleId` input has no default and
receives nothing will never match any gate (this was a real bug once), so keep the default on every one.

**Asset lookups:** the asset is resolved more than once per issue — the hub runs the helper to read the
provider, and each Azure L3 runs it again (the AWS dispatch does its own `core-get-asset-details`).
`asset_data` is not passed down. This is known and accepted for now (§9).

**Action tasks:** `continueonerror: true`, `continueonerrortype: errorPath`; `#error#` → the shared
"get Issue Recommendations" task, `#none#` → the shared "Set issue as fixed" task
(`Builtin|||setIssueStatus`, `Resolved - Fixed`). Arguments are plain `simple:` strings using
`${asset_data…}` — no `complex` transformer chains (except where a filter is really needed, as in
the Network rule-name lookups).

**Per-playbook notes (Azure v2):**
- *Network*: 5 labels (Common TCP Ports, ICMP Rules, Overly Permissive, Common UDP Ports, SSH (22))
  → a "find the offending rule name" chain (TCP/UDP set `protocol`, then `port` from the issue name
  via regex, then look up `ruleName`) → shared condition "Check rule name" (rule name non-empty AND
  source prefix in `0.0.0.0/0, ::/0, *`) → `azure-vn-security-rule-delete`; success → Set issue as
  fixed → Done; the check's default and the delete's error → recommendations → manual → Done.
- *Compute*: 7 labels; ACR ×3 and App Service/Function actions; recommendations fallback.
- *Identity*: still a single gate + one action (`azure-keyvault-vault-update`, the non-deprecated
  command) + `setIssueStatus`; its manual task keeps hardcoded portal steps instead of
  recommendations.
- *Data*: 7 labels; storage, disk, SQL, MySQL, Cosmos DB.

**AWS notes (v2):**
- Same pattern as Azure: helper first, one `Evaluate triggered rule` switch, action → `Set issue as
  fixed`, `#error#` → `get Issue Recommendations` → `Manually update asset` → Done. The per-rule
  hardcoded manual tasks of the old version (e.g. the EKS portal steps the user pasted) were replaced by
  the recommendations tail. The `incident.resourcename` output was kept only on Network.
- *Compute*: 6 labels (AMI Public, EC2 IMDSv2, ECS Container Insights, EKS Endpoint Public, ELB
  Cross-Zone, Lambda Function URL Auth). *Data*: 10 labels (EBS snapshot, 6 RDS, 3 S3). *Identity*:
  2 labels, one per IAM password-policy rule, both calling `aws-iam-account-password-policy-update` with
  different flags (account-level: only `account_id`). Tasks that share one command are named with a
  `(reason)` suffix (`aws-rds-db-instance-modify (IAM authentication)`).
- *Network*: 5 labels (SSH (22), RDP (3389), CIFS (445), Default SG Unrestricted, VPC Subnet Public IP).
  The legacy Security Group logic was kept as is: `Set port` → `Set protocol (tcp)` → find the offending
  rule's `from_port`/`to_port` → "Check rule open to internet" → `aws-ec2-security-group-ingress-revoke`;
  the Default SG path checks ingress and egress separately (`ingress-revoke` / `egress-revoke`, each
  marking `remediated`) and "Any rule remediated?" decides fixed vs manual. What changed: references now
  point to `asset_data`, and the removal tasks got `#error#` routes to the recommendations tail (they had
  none) and the success paths now end in `Set issue as fixed` (they went straight to Done before).
  `account_id` for the SG tasks is still derived from `securityGroupArn` by regex (re-rooted at
  `asset_data`); every other AWS task uses `${asset_data.xdm__asset__cloud__account__id}`.

## 4. Naming & tagging convention (applied)

Format: **`[GR][<Cloud>][<Role>] <Scope>`**

| Segment | Meaning | Allowed values |
|---|---|---|
| `[GR]` | family tag (groups all of these together in the list) | fixed |
| `<Cloud>` | cloud the playbook handles | `All` (hub only), `AWS`, `Azure`, `GCP` |
| `<Role>` | what it does | `Dispatch` = only calls other playbooks, never runs cloud commands (hub and L2). `Remediation` = runs the commands that fix (L3) |
| `<Scope>` | free text | hub: `Cloud provider`; L2: `Misconfiguration`; L3: one of `Network`, `Compute`, `Identity`, `Data` |

Current names, in list order:
```
[GR][All][Dispatch] Cloud provider
[GR][AWS][Dispatch] Misconfiguration
[GR][AWS][Remediation] Compute | Data | Identity | Network
[GR][Azure][Dispatch] Misconfiguration
[GR][Azure][Remediation] Compute | Data | Identity | Network
[helper] get-asset-details            (helpers keep the [helper] tag)
```
Rationale: bracket tags (user's preference); cloud first so each cloud groups together; `Dispatch`
sorts before `Remediation` so a cloud's router precedes its executors. Avoid `Router` as a role word
(it sorts after `Remediation`). `Foundation` in the old hub name was an *environment* (a group of
accounts) unrelated to the playbook's content, so it was dropped.

**Tags** (`tags:` list at playbook top level, right after `description`) repeat the name's bracket
segments, plus the category for `Remediation` playbooks:
`[GR][Azure][Remediation] Network` → `tags: [GR, Azure, Remediation, Network]`; hub → `[GR, All,
Dispatch]`; the helper only has `[helper]`. Name and tags carry the same information, so **update both
together** when renaming.

Other rules:
- No version/copy suffixes (`_2`, `(1)`, `v2`) in a playbook name or file name.
- File name = playbook name with spaces → `_` (e.g. `[GR][Azure][Remediation]_Network.yml`).
- `playbookName` on a `type: playbook` task must equal the target's `name:` **exactly**, and the
  task's own `name:` should match it. Renaming a playbook = also update every caller (hub, dispatches).
- **YAML: a value starting with `[` must be quoted** (`name: '[GR][Azure][Dispatch] Misconfiguration'`),
  otherwise it parses as a list and Cortex rejects the file.
- Task names: the central switch is always `Evaluate triggered rule`; action tasks are named after
  the command, with a `(reason)` suffix when the same command appears more than once
  (`azure-storage-account-update (secure transfer)`); shared tasks: `get Issue Recommendations`,
  `Set issue as fixed`, `Manually update asset`, `Done`.
- Context keys are snake_case (`asset_data`, `asset_index`, `ruleName`, `port`, `protocol`); inputs are
  camelCase (`ruleId`).

## 5. Category taxonomy

Four categories, same vocabulary in every cloud: **Network, Compute, Identity, Data.** Storage was
deliberately folded into `Data`; disk-type resources (Azure managed disk, AWS EBS snapshot) are in
`Data`; Azure Key Vault is in `Identity`; ACR / App Service / Function App / Logic App and AWS
AMI/EC2/ECS/EKS/ELB/Lambda are in `Compute`. GCP: firewall rules and subnets → `Network`; GKE clusters and
VM instances → `Compute`; Storage buckets → `Data`; GCP has no `Identity` rules yet, so there is no GCP
Identity playbook (add one, following §10.2, when such a rule appears). Several placements were judgment
calls made with the user — **confirm with the user before placing a new ambiguous rule.**

## 6. Full rule inventory (78 rules: 42 Azure + 23 AWS + 13 GCP)

### 6.1 Azure — 42 rules across 4 categories

**Network** — `[GR][Azure][Remediation] Network` (23 rules, all NSG; 5 switch labels):

| Rule | UUID |
|---|---|
| NSG Inbound rule overly permissive — any protocol | `840b475c-a50b-11e8-98d0-529269fb1459` |
| NSG Inbound rule overly permissive — TCP | `543c664a-a50c-11e8-98d0-529269fb1459` |
| NSG Inbound rule overly permissive — UDP | `d979e41c-a50d-11e8-98d0-529269fb1459` |
| NSG allows all traffic on SSH (22) | `3beed53c-3f2d-47b6-bb6f-95da39ff0f26` |
| NSG allows all traffic on RDP (3389) | `a36a7170-d628-47fe-aab2-0e734702373d` |
| NSG allows all traffic on NetBIOS DNS TCP (53) | `7a4a4cb3-8584-4844-ae91-4db22d115cd5` |
| NSG allows all traffic on FTP (21) | `1fb5d1ac-17f1-43f1-8bf6-aa73005175b6` |
| NSG allows all traffic on FTP-Data (20) | `ae2e5e26-4f3b-4bd3-9a8f-93fc2794607c` |
| NSG allows all traffic on MSQL (4333) | `79428a6c-0c5b-42af-a1a5-2f287a984d91` |
| NSG allows all traffic on MySQL (3306) | `8c36bb5c-2a53-4c58-97bf-2ccf2f4742fc` |
| NSG allows all traffic on Windows RPC (135) | `cb1fb96b-919f-4042-a745-cd070497f475` |
| NSG allows all traffic on Windows SMB (445) | `c446ec59-db8f-47a1-ace1-cfe6cd366982` |
| NSG allows all traffic on PostgreSQL (5432) | `b498a297-ae00-43ee-b767-d458785c7e00` |
| NSG allows all traffic on SMTP (25) | `63199794-1208-4e6b-aa02-c257f84a6e6b` |
| NSG allows all traffic on SQL Server TCP (1433) | `65c342f9-1663-4114-bb70-f3ef303aa561` |
| NSG allows all traffic on Telnet (23) | `d148612d-6f2e-455a-89fc-a1e917fa715f` |
| NSG allows all traffic on VNC (5500) | `23c0c9e7-bef8-4c41-a9ec-b5b670667afa` |
| NSG allows all traffic on ICMP (Ping) | `5c1e59f6-2e1a-4d2e-8864-00a8365ac10a` |
| NSG allows all traffic on CIFS UDP (445) | `0f7fb1e1-dc2b-431f-8dad-efdeae05ebcb` |
| NSG allows all traffic on NetBIOS UDP (137) | `e51a22c2-f8d1-4f12-86ad-f64751ba3406` |
| NSG allows all traffic on NetBIOS UDP (138) | `5b2a3e46-799c-4ae7-b918-e4679ade50cb` |
| NSG allows all traffic on SQL Server UDP (1434) | `0113c405-c954-4ace-9d94-f0e9728bdf03` |
| NSG allows all traffic on NetBIOS DNS UDP (53) | `4f0dc13f-88d1-4820-8e9b-3e04779b0da9` |

**Compute** — `[GR][Azure][Remediation] Compute` (9 rules, 7 switch labels; the 3 HTTPS-redirect rules share one label/action):

| Rule | UUID |
|---|---|
| Container Registry anonymous auth enabled | `e2b13b04-34b0-455d-8d50-8e01e5ae7947` |
| Container Registry ARM audience token auth enabled | `174428c5-b6fa-49fc-87cb-f9af04d5b55d` |
| Container Registry exports enabled | `91415843-d808-4c11-97cf-c66414c628b5` |
| App Service web app doesn't redirect HTTP to HTTPS | `c6c62207-dbf7-45a1-b809-e1c896eb28fb` |
| Function App doesn't redirect HTTP to HTTPS | `82d945cb-49c0-4163-89ef-7ac3c194d4cb` |
| Logic App doesn't redirect HTTP to HTTPS | `2a377921-af8b-4c81-bba8-121f94b9ded4` |
| App Services remote debugging enabled | `1feba014-ed3b-46ed-8a7c-4c03ec1469b7` |
| Function App doesn't use latest TLS version | `c82a5f89-cd01-4bcf-8fa3-99396a4c848d` |
| Function App has no Managed Service Identity | `0649ae20-3c76-4134-851f-70a7b65c03ec` |

**Identity** — `[GR][Azure][Remediation] Identity` (1 rule):

| Rule | UUID |
|---|---|
| Key Vault purge protection not enabled | `df4f009d-f049-4e04-bbdf-06d98b1b040f` |

**Data** — `[GR][Azure][Remediation] Data` (9 rules, 7 switch labels; the 3 "storage public access" rules share one label/action):

| Rule | UUID |
|---|---|
| Storage Account without secure transfer enabled | `4a6a7642-06f0-4e51-aa79-a7c06afffdc5` |
| VM disk with overly permissive network access | `6a3ba52c-1a0e-4359-aba5-e417ca280270` |
| Storage account blob container with public access | `c085d057-d5a4-4118-afdf-f653e6b47995` |
| Storage Account Cognitive Services diagnostic logs public | `af7266ac-1506-4251-9294-34c8b2f67ab5` |
| Storage Account 'Trusted Microsoft Services' access not enabled | `04aaadfc-65e0-4347-9a3e-1922e9a2068e` |
| Storage account activity-log container public | `499c23da-b67f-441a-81e3-9fc0fd05ea75` |
| SQL database TDE disabled | `5a772daf-17c0-4a20-a689-2b3ab3f33779` |
| MySQL flexible server SSL enforcement disabled | `50ba3795-c6c7-43f2-af00-5162cb1a14f3` |
| Cosmos DB key-based authentication enabled | `ef14d0a6-8ed0-4f7a-9877-15efa3194737` |

### 6.2 AWS — 23 rules across 4 categories

**Network** — `[GR][AWS][Remediation] Network` (5 rules):

| Rule | UUID |
|---|---|
| Security Group allows all traffic on SSH (22) | `62c42bbc-1764-408f-814c-68d2b392af1f` |
| Security Group allows all traffic on RDP (3389) | `0351493c-9989-4b33-ad86-18dbe406e710` |
| Security Group allows all ingress on CIFS (445) | `261ba538-fa6a-418c-b6de-441bb1d4e593` |
| Default Security Group does not restrict all traffic | `8824de78-7e99-4ef2-9c3d-8110e12c7df7` |
| VPC subnets allow automatic public IP assignment | `11743cd3-35e4-4639-91e1-bc87b52d4cf5` |

**Compute** — `[GR][AWS][Remediation] Compute` (6 rules):

| Rule | UUID |
|---|---|
| AMI publicly accessible | `81a2200a-c63e-4860-85a0-b54eaa581135` |
| EC2 instance not on IMDSv2 | `81c165ce-f66e-441a-8ea0-56a107175ccc` |
| ECS cluster container insights disabled | `577ef22c-f4c5-4a54-8aa0-cc6f58275777` |
| EKS cluster endpoint publicly accessible | `4b508cb7-9a42-4ad2-a2e3-ed3921e00015` |
| Classic ELB cross-zone load balancing disabled | `194dc989-ec4c-426c-826f-d7365d9a59ed` |
| Lambda function URL AuthType = NONE | `92a3fce2-0875-49da-af5c-71c3366100bf` |

**Identity** — `[GR][AWS][Remediation] Identity` (2 rules):

| Rule | UUID |
|---|---|
| IAM password policy has no number requirement | `9a5813af-17a3-4058-be13-588ea00b4bfa` |
| IAM password policy is insecure (general) | `1e0076af-0ccd-4f1c-bba5-ac92964a5e6b` |

**Data** — `[GR][AWS][Remediation] Data` (10 rules):

| Rule | UUID |
|---|---|
| EBS snapshot publicly accessible | `7c714cb4-3d47-4c32-98d4-c13f92ce4ec5` |
| RDS cluster without IAM authentication | `f79f0e00-fcf1-49ef-ab0c-b3db225b086d` |
| RDS cluster snapshot publicly accessible | `4db5ec62-c7cd-4725-adba-fdd30eb911a3` |
| RDS instance publicly accessible | `b3897fb4-5241-403b-8770-69f90cea0f11` |
| RDS instance without IAM authentication | `005ab558-f5e8-49e4-b472-7bad3f70987a` |
| RDS instance without auto minor version upgrade | `d280f6cc-20ce-41e2-a29e-e23c6b3f8b6d` |
| RDS instance snapshot publicly accessible | `a707de6a-11b7-478a-b636-5e21ee1f6162` |
| S3 bucket ACLs in use | `b8e3f191-9cfb-4707-8a82-cb5f784f7694` |
| S3 bucket publicly accessible via ACL | `67dc23e7-e6db-4efb-b7e8-b4bd7778c891` |
| S3 bucket block-public-access disabled | `b22df320-13e7-4108-8142-d1bd858b8d46` |

### 6.3 GCP — 13 rules across 3 categories

**Network** — `[GR][GCP][Remediation] Network` (8 rules, 2 switch labels; the 7 firewall rules share one label/action, which *disables* the rule):

| Rule | UUID |
|---|---|
| Default firewall rule is overly permissive (except http and https) | `a1d88a90-aede-4678-8e01-6cc08074bcf5` |
| Firewall rule allows all traffic on RDP port (3389) | `34175634-0e4a-4e9d-9c77-0c75390b8bdc` |
| Firewall rule allows all traffic on SSH port (22) | `49a154e8-6049-4317-bbb5-0c90cb078f94` |
| Firewall rule allows inbound traffic from anywhere with no specific target set | `ac2aef26-939c-40e9-9aae-2e9be6fd7d0a` |
| Firewall rule exposes GKE clusters by allowing all traffic on port 10250 | `c88e6b00-3e5f-4073-a091-e9be8747cf20` |
| Firewall rule exposes GKE clusters by allowing all traffic on read-only port (10255) | `8a28c396-0a6f-4958-84e2-9c74c5911ae5` |
| Firewall with inbound rule overly permissive to all traffic | `33142dd4-733b-44d1-8320-8ccacf39adf9` |
| VPC network subnets have Private Google access disabled | `899e01c6-9092-44a8-ae43-1f8a891b01b6` |

**Compute** — `[GR][GCP][Remediation] Compute` (2 rules, 2 switch labels; the VM rule is routed straight to the recommendations/manual path, see gotcha 15):

| Rule | UUID |
|---|---|
| Kubernetes Engine clusters have master authorized networks disabled | `1bf2e381-28ab-4354-9f00-920d200be18f` |
| VM instances have block project-wide SSH keys feature disabled | `8ae5d48f-8f65-4844-8f32-c83e1d6626ba` |

**Data** — `[GR][GCP][Remediation] Data` (3 rules, 3 switch labels: authenticated users → `gcp-storage-bucket-policy-delete entity=allAuthenticatedUsers`, all users → `entity=allUsers`, public logs → chain `allUsers` then `allAuthenticatedUsers`; see gotcha 15):

| Rule | UUID |
|---|---|
| Storage buckets are publicly accessible to all authenticated users | `9f08e13c-cdd6-4ad1-89f5-ffef6a71e432` |
| Storage buckets are publicly accessible to all users | `41f7a4b1-cad6-4fbf-b698-1fd11a8869a8` |
| Storage buckets with publicly accessible GCP logs | `eddabf29-fa96-4e14-ab4d-74245824c212` |

> These tables are the **source of truth** for rule → UUID → category. Earlier in the project the
> monolithic files carried this mapping as a YAML comment, but that was lost when files were regenerated
> (`yaml.dump` does not preserve comments). Update this section, not a YAML comment, whenever a rule
> is added or moved.


## 7. Asset field-mapping conventions

**Azure (v2)** — all via the helper's `asset_data`:

| Need | Expression |
|---|---|
| Subscription | `${asset_data.xdm__asset__cloud__account__id}` |
| Resource name | `${asset_data.xdm__asset__raw_fields.Platform Discovery.name}` |
| Resource group | `${asset_data.xdm__asset__raw_fields.Platform Discovery.resourceGroup}` (Network's remove task uses `asset_data.xdm__asset__normalized_fields_by_source` → `Platform Discovery` → `xdm.asset.resource_group` instead) |
| SQL / MySQL server name | `${asset_data.xdm__asset__raw_fields.Platform Discovery.serverName}` — **unverified guess**; if wrong those two actions fall to the manual path |
| NSG rules | `asset_data.xdm__asset__raw_fields.Platform Discovery.properties.securityRules…` (used in filters) |

**AWS (v2)** — also via the helper's `asset_data`; generic fields plus resource-specific raw fields:

| Need | Expression |
|---|---|
| Account id | `${asset_data.xdm__asset__cloud__account__id}` |
| Region | `${asset_data.xdm__asset__cloud__region}` (a plain string, confirmed by the user) |

Resource-specific fields live under `asset_data.xdm__asset__raw_fields."Platform Discovery"` (in the old
model: `Core.CoreAsset.[0].xdm__asset__raw_fields…`) and were **confirmed by the user against real assets** (casing is inconsistent across AWS resource
types — a real quirk, not something to "clean up"; ask the user to check a real asset before adding one):

| AWS resource | Field (relative to `"Platform Discovery"`) |
|---|---|
| AMI | `image.imageId` |
| EBS snapshot | `snapshot.snapshotId` |
| EC2 instance | `instanceId` |
| VPC subnet | `subnetId` |
| ECS cluster | `clusterName` |
| EKS cluster | `name` |
| Classic ELB | `LoadBalancerName` |
| Lambda function | `FunctionName` |
| RDS cluster | `DBClusterIdentifier` |
| RDS cluster snapshot | `DBClusterSnapshotIdentifier` |
| RDS instance | `DBInstanceIdentifier` |
| RDS instance snapshot | `Snapshot.DBSnapshotIdentifier` |
| S3 bucket | `Properties.BucketName` |

**GCP (v2)** — verified against real **firewall rule**, **VPC subnet**, **GKE cluster**, **Storage bucket** and **VM instance**
assets (the user pasted their `asset_data`). Ask the user to check a real asset of each remaining type (as was done for
AWS, where 8 of 13 first guesses were wrong) and fix the paths:

| Need | Expression used | Status |
|---|---|---|
| Project id (`project_id`) | `${asset_data.xdm__asset__cloud__account__id}` | **verified**: holds the project id (e.g. `fp-cloud-gov-466719`) |
| Provider (hub routing) | `asset_data.xdm__asset__provider` | **verified**: `GCP` |
| Resource name (firewall, subnet, GKE cluster, VM instance, bucket) | `${asset_data.xdm__asset__name}` | the user's final choice, the same for every GCP type (VM included, so all are uniform). A top-level field, so no `complex`/dotted-key handling. **Verified** on the firewall (`default-allow-ssh`), subnet (`default-1`), GKE (`gke-partner-xp-prod`) and bucket (`stg-tau-rex-static-content`) assets, where it equals both the normalized `xdm.asset.name` and the raw `name`; also **verified on the VM** (`azdevops-agent-556q`) |
| Bucket asset facts | type id `GOOGLE_CLOUD_STORAGE_BUCKET` | `project_id` = the bucket's own project (`stg-tau-rex`). Raw fields carry `iam.bindings` (here an `allUsers` `legacyObjectReader` binding) and `iamConfiguration.publicAccessPrevention` (`inherited`), the very setting the remediation sets to `enforced` |
| Firewall asset facts | type id `GOOGLE_VPC_FIREWALL_RULE` | raw fields also carry `disabled`, `sourceRanges`, `allowed`, `direction`, `network` |
| Subnet asset facts | type id `GOOGLE_VPC_SUBNET` | raw fields also carry `privateIpGoogleAccess`, `region` (a URL), `network` |
| GKE cluster asset facts | type id `GOOGLE_KUBERNETES_ENGINE_CONTAINER_CLUSTER` | its `project_id` is the cluster's own project (`xdm__asset__cloud__account__id` matches the `projects/…` in `external_provider_id`) |
| Subnet `region` | `${asset_data.xdm__asset__cloud__region}` | **verified**: a plain region (`us-east1`). (A firewall shows `global`; the raw `region` field on the subnet is a URL, so the generic field is the right one to use) |
| GKE cluster `region` argument | `${asset_data.xdm__asset__raw_fields.Platform Discovery.location}` | **verified on both kinds**: a regional cluster (`gke-partner-xp-prod`) has `location` = `us-east1` (= generic region); a **zonal** cluster (`my-first-cluster-1`, `strong_id` `…/zones/us-central1-c/clusters/…`) has `location` = `us-central1-c` while the generic `xdm__asset__cloud__region` is only `us-central1` — so the generic field would be wrong for zonal clusters. The raw fields also carry `zone` (= `location` on both) and `masterAuthorizedNetworksConfig` (`enabled`, optional `cidrBlocks[]`). Open point: the update command documents `region` as "GCP region", but the sibling `gcp-gke-cluster-get` documents the same argument as "the GCP location (zone or region)", which strongly suggests a zone is accepted; confirm by running |
| VM `zone` | `complex`: `getField zone` + `RegexExtractAll ([^/]+)$` | **verified**: `raw_fields.Platform Discovery.zone` is a URL (`…/zones/us-east1-b`); the regex takes the last segment (`us-east1-b`). The generic region on the VM is `us-east1`, so the zone must come from this field. VM asset type id `GOOGLE_COMPUTE_ENGINE_VM_INSTANCE`; the same zone URL is also at `xdm__cloud__zone`. Raw `metadata.items` is a list of `{key, value}` |

Command names/arguments come from the integration README on
`github.com/demisto/content` (`Packs/Azure|AWS|GCP/Integrations/<name>/README.md`; the GCP integration id
is `GCP`, so scripts are `GCP|||gcp-…`) — more reliable than the summarised xsoar.pan.dev pages.

## 8. Gotchas (avoid repeating them)

1. **Content index limit on `description`.** A long description (e.g. all rules + UUIDs) fails with
   `Data too long for column 'description'`. Keep it to a sentence or two; the full inventory lives here.
2. **JSON-looking `simple:` values must be quoted**: `simple: '{"endpointPublicAccess": false, …}'`,
   otherwise YAML parses a mapping and Cortex fails with `cannot unmarshal !!map into string`.
3. **Names starting with `[` must be quoted** (see §4).
4. **Every switch label needs a `nexttasks` route.** A label defined in `conditions` but missing from
   `nexttasks` silently drops that rule (this happened to "ACR Exports Enabled").
5. **A task with two `#none#` targets runs both in parallel.** The Network SSH path once pointed to
   both the "Check rule name" gate and the delete action, so the delete ran unconditionally.
6. **Sub-playbook `ruleId` needs a default** (§3) or the switch never matches.
7. **Use `inputs.<name>` (plural) to reference playbook inputs.** `${input.x}` was a typo once.
   Don't declare inputs nobody reads (the Azure dispatch still has unused `portNumber`, `asset_data`).
8. **`yaml.dump` drops comments and reformats.** Fine for generated files; for user-exported files
   prefer surgical text edits, and never put documentation in YAML comments (put it here).
9. **Task IDs only need to be unique within a file**, and each task's `id` must equal its dict key;
   the `taskid` UUID is separate and must stay stable.
10. **The Cortex command `azure-cosmosdb-db-account-update` has no `disable_local_auth`** argument, so
    the Cosmos DB "key-based auth" remediation only disables key-based *metadata writes*. The user
    knowingly accepted this and it is still marked "fixed" on success.
11. Playbook and content names in a tenant collide by name on import: the old `Remediation - Azure …`
    (and `… Compute_2`, etc.) playbooks may still exist in Cortex and should be deleted.
12. **(historical — the automated VM chain was removed, see 15)** **`gcp-compute-instance-metadata-set` replaces ALL instance metadata** (any key not sent, including
    `ssh-keys` and `startup-script`, is removed) and takes it in a delimiter format
    (`key=a,value=1;key=b,value=2`) that breaks on values containing `,` or `;` (startup scripts) and has no
    safe way to be rebuilt from a list inside a playbook. The GCP Compute playbook therefore only runs it when
    the instance has **no** metadata items (`gcp-compute-instance-get` → `Instance has no other metadata?`),
    otherwise it falls to the recommendations/manual path. (The sample VM the user pasted has 4 items, one being
    a `gce-container-declaration` with newlines and quotes, so it correctly goes to the manual path. Note also that
    VM metadata can hold secrets, and the full asset `asset_data` carries them: treat pasted assets and playbook
    context/war-room output accordingly. And an instance created by a managed instance group gets its metadata
    from the instance template, so a direct change may not survive re-creation; the sample VM was in fact
    re-created between the asset snapshot and the live `instance-get` — different `id`, `creationTimestamp` and IP —
    which is also why the guard reads the live instance rather than the asset's `metadata`.) The user had asked for full recomposition; this
    guarded version was implemented instead and should be revisited if they want to go further (e.g. a
    custom automation script).
13. **`gcp-container-cluster-security-update` with `enable_master_authorized_networks=true` and no CIDRs
    blocks all access to the GKE master.** Implemented as-is on the user's decision (it mirrors what Prisma
    Cloud ran: `gcloud container clusters update … --enable-master-authorized-networks`). Possible improvement
    (not implemented): pass the CIDRs already configured on the cluster
    (`raw_fields…masterAuthorizedNetworksConfig.cidrBlocks[].cidrBlock`, joined with commas) as `cidrs`, so a
    cluster that has a list saved but disabled isn't locked out.
14. GCP firewall remediation **disables** the rule (`gcp-compute-firewall-patch disabled=true`) instead of
    deleting it or narrowing `sourceRanges` (a rule with no source ranges/tags/service accounts defaults to
    `0.0.0.0/0`). Disabling the *default* network's `default-allow-*` rules can break VM-to-VM traffic.
15. **The user's tenant has an older GCP pack than the public docs.** The `!gcp-` command list the user pasted
    (40 commands) lacks `gcp-gke-cluster-get` (added in pack 1.18.0), `gcp-compute-instance-metadata-set`
    (1.7.0) and `gcp-storage-bucket-public-access-block` (1.4.0); it does contain `gcp-compute-firewall-patch`,
    `gcp-compute-subnet-update`, `gcp-compute-instance-get`, `gcp-storage-bucket-policy-delete` and both
    `gcp-container-cluster-security-update` (deprecated since 1.3.0) and `gcp-gke-cluster-security-update`.
    Always check a command against the user's `!gcp-` list, not the master README. Adaptations made (user chose
    "adapt to the current version"): **VM SSH-keys rule → manual** (label routes straight to `get Issue
    Recommendations`; the guarded metadata chain is gone, restore it if the pack is updated to ≥ 1.7.0);
    **buckets → `gcp-storage-bucket-policy-delete`** with `entity` = `allAuthenticatedUsers` / `allUsers` per rule
    (README says "Access Control List" but the required permissions are IAM `getIamPolicy/setIamPolicy`, so it
    is **untested** whether it removes the IAM binding; test on a throwaway bucket. It may also error if the
    entity isn't present, which lands in the manual path); **public-logs bucket rule → chain of two deletes**
    (`allUsers`, then `allAuthenticatedUsers`, since the rule doesn't say which entity makes it public; an error on
    the first still continues to the second, an error on the second goes to manual, so a bucket where only one of
    the entities existed ends in the manual path even though it was fixed; a real failure of the first followed by
    a success of the second could mark the issue fixed while `allUsers` remains, unlikely since both need the
    same permissions). If the pack is updated, `gcp-storage-bucket-public-access-block`
    (`public_access_prevention=enforced`) is the better fix for all 3 bucket rules. Optionally switch the GKE
    task to the non-deprecated `gcp-gke-cluster-security-update` (same arguments).

## 9. Known open items

- **Azure dispatch**: unused inputs `portNumber` and `asset_data`; a meaningless output
  `incident.resourcename` ("Security group name"); no `#default#`/`#error#`.
- **Hub**: now depends on the helper (stops silently for issues without exactly one asset; the helper call
  has no `#error#`), and on `asset_data.xdm__asset__provider` holding exactly `AWS` / `AZURE` / `GCP`
  (not verified by the assistant). The asset is resolved twice per Azure issue (hub + L3). Possible
  later refactor: pass `asset_data` down and drop the helper calls in L3.
- **Helper**: the "Evaluate index" condition has two labels with the *same* condition
  (`asset_index == -1`); the original used `!= -1` for "asset loaded". Works today only because the
  isolated context always yields `-1`. It also stops silently if the issue has more than one asset.
- **Hub**: the Azure call (task `11`) carries a `loop` block (`max: 100`, empty `exitCondition`) that the
  AWS call doesn't; verify it's intended. `GCP` label unrouted.
- **Azure Compute**: tasks `3` and `6` are both named plain `azure-cr-registry-update` (cosmetic).
- **Azure Identity** still uses hardcoded manual steps (other v2 playbooks use recommendations) and
  names its status task `setIssueStatus` instead of `Set issue as fixed`.
- **Azure Data**: `serverName` unverified (§7).
- **AWS**: migrated to v2 but **never imported or run in Cortex**. Points to verify: the asset field paths
  under `asset_data` (§7) in a real run; that the account-level IAM password-policy issues carry a usable
  `asset_data.xdm__asset__cloud__account__id`; the legacy SG chain (`ruleFromPort`/`ruleToPort` lookups over
  `ipPermissions`) now that it reads `asset_data`; and the same helper/hub caveats as Azure.
- **GCP**: built but **never imported or run**. Verified from a real firewall asset: project id, provider `GCP`,
  all five asset types' names (`xdm__asset__name`), the subnet `region`, the GKE cluster `location` and the VM `zone`.
  The context path `GCP.Compute.Instances.metadata.items` used by the metadata guard is **verified**: the user ran
  `!gcp-compute-instance-get`, whose output lands at `GCP.Compute.Instances` (an object, not a list) at the same level
  as `asset_data`, with `metadata.items` = list of `{key, value}`. GKE `location` is also **verified on a zonal
  cluster** (see §7). **Still unverified:** that the update command's `region` argument accepts a zone at run time (no `gke-cluster-get` exists in the installed pack to test read-only) and that `gcp-storage-bucket-policy-delete` removes the public IAM binding (gotcha 15). The GCP dispatch/Compute/Network/Data
  playbooks inherit the same helper/hub caveats as Azure. No `Identity` playbook exists for GCP.
- Repo cleanup done: the obsolete v1 Azure folder and the scratch export at the repo root were deleted, and `azure-remediation-v2/` was renamed to `azure-remediation/`. Old `Remediation - Azure …` playbooks may still exist in the tenant (gotcha 11).

## 10. How to extend

### 10.1 Add a rule to an existing Azure category (v2)
1. Get the command and argument names from the integration README (§7) and confirm the resource
   field with the user if it isn't `name`/`resourceGroup`.
2. In `[GR][Azure][Remediation] <Category>`: if the action is identical to an existing label's, add the
   rule's UUID to that label's OR-list. Otherwise add a new label to "Evaluate triggered rule", **route it
   in `nexttasks`**, and add an action task (`#error#` → `get Issue Recommendations`, `#none#` →
   `Set issue as fixed`).
3. In `[GR][Azure][Dispatch] Misconfiguration`, add the UUID to that category's label.
4. Add the row to §6 of this file. 5. Validate (§10.6).

### 10.2 Add a category
Only if a rule truly doesn't fit the four; confirm with the user first. Create the L3 playbook
following §3 and §4 (name, tags, helper first, switch, shared tail), add a label + a
`type: playbook` call (`separatecontext: true`, `ruleId`) to the cloud's dispatch, update §5/§6.

### 10.3 Rename a playbook
Keep the `id`. Update `name:`, the `tags:`, every caller's `name`/`playbookName`, the file name, and
this document. Quote names that start with `[`.

### 10.4 How the AWS migration to v2 was done (reference)
Done once, programmatically, using the Azure v2 files as templates. To repeat it for another cloud: for each
L3, replace the fan-out/gates with one `Evaluate triggered rule` condition (labels = the old titles, rule IDs
= the old gates' OR-lists), call the helper first, convert `Core.CoreAsset.[0].…` to `asset_data.…` (single
`getField` arguments become `${asset_data.xdm__asset__raw_fields.Platform Discovery.<field>}`; anything with
filters/regex is kept as `complex` and only re-rooted), send action `#error#` to the recommendations tail
and `#none#` to one shared `Set issue as fixed`, drop per-rule manual tasks. For the dispatch: drop the
integration check and asset chain, use the central switch with `separatecontext: true` and no arguments.
Keep each playbook's `id`, `name` and `tags`. Legacy multi-step chains (like the AWS Security Group paths)
are kept and only re-rooted. A backup of the old AWS files was made before the migration.

### 10.5 GCP: what exists and how it was built (reference)
GCP was built once, programmatically, in the v2 pattern: `[GR][GCP][Dispatch] Misconfiguration` (3 labels) +
`[GR][GCP][Remediation] Network / Compute / Data`, each with the helper, one `Evaluate triggered rule`
switch, and the shared tail. In the hub, task `14` calls the GCP dispatch and the `GCP:` label routes to it
(mirrors tasks `11`/`12`). To add a GCP rule, follow §10.1 with the `GCP|||gcp-…` commands. Decisions taken
with the user: firewall → disable; GKE → enable master authorized networks without CIDRs; VM SSH keys and buckets
were adapted to the commands available in the installed pack (gotcha 15: VM manual, buckets `policy-delete`).
**Next step for GCP is verification with real assets** (§7, §9), not new development.

### 10.6 Validation checklist (run after every change)
- File parses (`yaml.safe_load`); every `nexttasks` target exists; no orphan tasks; every switch label has a route.
- Every `simple:` script argument is a string; every task `id` equals its key; `taskid` UUIDs unique.
- Every `playbookName` in the hub/dispatches equals an existing playbook `name:`.
- Each dispatch category label's rule-ID set equals the union of IDs in the matching L3 playbook.
- After renames: `id`s unchanged; `tags` match the name.
- No `Core.CoreAsset` left in v2 playbooks (except inside the helper).

A minimal Python check (~15 lines) covering the first and third bullets is enough; write it fresh each time.

## 11. Working agreements with the user

- The user edits playbooks in the Cortex UI and re-exports them over the repo files. **Always re-read the
  file before editing**; never assume it still matches what you last wrote.
- They organise the canvas layout themselves and like the current layouts. **Don't reposition tasks
  unless asked**, and don't renumber task IDs unasked (they asked once for small sequential IDs on one file).
- Discuss before implementing when asked to evaluate ("avalie … não altere"); when asked to apply, do the
  requested corrections only and list what you left alone.
- Flag problems you notice in files you were only asked to renumber/review; fix them only on request.
- Communicate in Portuguese; keep this document in English (it is for other agents).
