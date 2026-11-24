"""Diagram specs for the Policy-as-Code Baseline. Edit here, run gen.py, commit both."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "controls"))
from definitions import CONTROLS
META = "Policy-as-Code Baseline (multicloud) | Adamson-lab"


def N(i, l, k, a, s=None):
    return (i, l, k, a, s)


def G(label, color, nodes, cols=1, below=False, style=None):
    return dict(label=label, color=color, nodes=nodes, cols=cols, below=below, style=style)


def S(slug, title, sub, audience, notation, scope, groups, edges, notes=(), legend=None, rowlink=False):
    return dict(slug=slug, title=title, sub=sub, audience=audience, notation=notation, scope=scope, groups=groups, edges=edges, notes=list(notes), legend=legend or {}, rowlink=rowlink)


MECH = {"PAC-001": ("SCP: guard PAB", "allowBlobPublicAccess", "publicAccessPrevention"), "PAC-002": ("SCP: Encrypted=true", "keySource=KeyVault", "restrictNonCmek"),
        "PAC-003": ("SCP: RequestedRegion", "Allowed locations", "resourceLocations"), "PAC-004": ("SCP: public IP launch", "NIC public IP deny", "vmExternalIpAccess"),
        "PAC-005": ("SCP: SecureTransport", "HTTPS traffic only", "restrictTLSVersion"), "PAC-006": ("SCP: CreateAccessKey", "allowSharedKeyAccess", "disableSaKeyCreation"),
        "PAC-007": ("SCP: guard CloudTrail", "AuditIfNotExists", "Aggregated log sink"), "PAC-008": ("SCP: RequestTag", "Require tag (Indexed)", "Custom constraint"),
        "PAC-009": ("Config: RDS public", "SQL publicNetwork", "sql.restrictPublicIp"), "PAC-010": ("Config: open ingress", "NSG source deny", "Custom: firewall CEL"),
        "PAC-011": ("SCP: IMDSv2 required", "VM password auth", "requireOsLogin"), "PAC-012": ("SCP: default VPC", "Subnet outbound audit", "skipDefaultNetwork")}
FKIND = {"full": "storage", "partial": "compute", "compensating": "sec"}
SHORT = {"PAC-001": "Block public storage", "PAC-002": "Customer-managed keys", "PAC-003": "Approved regions only", "PAC-004": "No public IPs", "PAC-005": "TLS 1.2+ in transit", "PAC-006": "No long-lived creds",
         "PAC-007": "Protect audit logging", "PAC-008": "Cost-center tag", "PAC-009": "No public databases", "PAC-010": "No world-open ingress", "PAC-011": "Hardened instance access", "PAC-012": "No default network"}
MLEG = {"mgmt": "Control", "db": "OPA / Rego (Terraform plan)", "storage": "Full fidelity", "compute": "Partial (gap documented)", "sec": "Compensating control"}


def matrix(part, ids, n):
    cs = [c for c in CONTROLS if c["id"] in ids]
    cols = [G("Control", "ctl", [N("c" + c["id"][-3:], f"{SHORT[c['id']]}|{c['id']} {c['severity']}", "mgmt", c["id"][-3:]) for c in cs]),
            G("OPA / Rego", "pur", [N("r" + c["id"][-3:], f"Plan gate|{len(c['tf'])} rules, generated", "db", "OPA") for c in cs])]
    for key, nm, col, ab in (("aws", "AWS SCP / Config", "aws", "SCP"), ("azure", "Azure Policy", "az", "AZ"), ("gcp", "GCP Org Policy", "gcp", "ORG")):
        idx = {"aws": 0, "azure": 1, "gcp": 2}[key]
        cols.append(G(nm, col, [N(key + c["id"][-3:], f"{MECH[c['id']][idx]}|{c[key]['kind'][:10]} / {c[key]['fidelity']}", FKIND[c[key]["fidelity"]], ab if c[key]["kind"] == "preventive" else "DET") for c in cs]))
    return S(f"control-mapping-{part}", f"1:1 control mapping ({part.replace(chr(45), chr(32))})", f"Controls {ids[0]} to {ids[-1]} mapped to four engines, fidelity stated honestly", "Architect / auditor", "Mapping matrix", "Control catalogue",
             cols, [], ["Every row exists in all four engines. Colour = fidelity; gaps are documented in docs/mapping-matrix.md and enforced by tools/verify_parity.py."], MLEG, rowlink=True)


SPECS = [
S("business-context", "Business context (C4 level 1)", "Who sets guardrails, who consumes them, and which systems the baseline touches", "Executive", "C4 system context", "Whole programme",
  [G("Governance and risk", "gry", [N("ciso", "CISO|risk appetite", "user", "CISO"), N("grc", "GRC and audit|evidence consumers", "user", "GRC"), N("ccoe", "Cloud CoE|control authors", "user", "CoE"), N("arb", "Architecture board|waiver decisions", "user", "ARB")], cols=2),
   G("System in scope", "ctl", [N("pac", "Policy-as-Code|Baseline", "mgmt", "PaC", "12 controls x 4 engines")]),
   G("Delivery", "gry", [N("dev", "App teams|consume guardrails", "user", "APP"), N("plat", "Platform engineering|run pipelines", "user", "PLT")]),
   G("Cloud estates", "gry", [N("aws", "AWS Organization|SCP + Config", "compute", "AWS"), N("az", "Azure tenant|Policy initiative", "az", "AZ"), N("gcp", "GCP organization|Org Policy", "gcp", "GCP")]),
   G("Enterprise systems", "gry", [N("git", "GitHub|source + reviews", "ext", "GH"), N("snow", "ServiceNow|exceptions", "ext", "SN"), N("siem", "SIEM / GRC tool|evidence", "ext", "GRC")])],
  [("ciso", "pac", "risk appetite"), ("ccoe", "pac", "authors controls"), ("arb", "pac", "approves waivers"), ("grc", "pac", "evidence packs"), ("dev", "pac", "plan checks in PRs"), ("plat", "pac", "operates pipeline"),
   ("pac", "aws", "SCP + Config"), ("pac", "az", "Policy + exemptions"), ("pac", "gcp", "Org Policy"), ("pac", "git", "release", "dash"), ("pac", "snow", "waivers", "dash"), ("pac", "siem", "compliance data", "dash")],
  ["Driver: four policy languages drift apart unless one catalogue generates them and one gate proves they still map 1:1."]),

S("capability-map", "Policy governance capability map (heat-mapped)", "Capabilities coloured by target maturity at go-live", "Executive / architect", "ArchiMate strategy viewpoint", "Capability layer",
  [G("Author and design", "ctl", [N("a1", "Control catalogue|single source", "storage", "CAT"), N("a2", "Framework mapping|NIST, CIS, ISO", "compute", "FW"), N("a3", "Fidelity model|full, partial, comp.", "storage", "FID"), N("a4", "Reversibility rating|one-way, two-way", "sec", "REV")]),
   G("Test and certify", "aws", [N("t1", "Rego unit tests|generated", "storage", "OPA"), N("t2", "Parity gate|1:1 proof", "storage", "PAR"), N("t3", "Canary scope|per cloud", "compute", "CAN"), N("t4", "Impact simulation|what-if", "sec", "SIM")]),
   G("Release and deploy", "az", [N("r1", "Signed releases|semver", "compute", "REL"), N("r2", "Staged promotion|waves", "compute", "PRM"), N("r3", "Audit then enforce|modes", "storage", "MOD"), N("r4", "Rollback|minutes", "compute", "RBK")]),
   G("Assess and assure", "gcp", [N("s1", "Compliance scoring|3 clouds", "compute", "SCR"), N("s2", "Drift detection|nightly", "compute", "DRF"), N("s3", "Evidence generation|audit packs", "compute", "EVD"), N("s4", "Waiver expiry|auto sweep", "storage", "EXP")]),
   G("Govern", "grn", [N("g1", "Policy board|monthly", "compute", "BRD"), N("g2", "Decision rights|thresholds", "storage", "DEC"), N("g3", "KPIs|coverage, MTTR", "compute", "KPI"), N("g4", "Training|app teams", "sec", "TRN")])],
  [("a1", "t1", "generates tests"), ("t2", "r1", "gates release"), ("r3", "s1", "feeds scoring"), ("s4", "g1", "expiries reviewed"), ("g2", "a1", "approves changes", "dash")],
  ["Green = built and tested here, orange = designed and to be proven in sandbox, red = people/process capability to build."],
  {"storage": "Strong (built + tested)", "compute": "Partial (designed)", "sec": "Gap (needs build)"}),

S("value-stream", "Policy lifecycle value stream", "From risk finding to enforced, measured and eventually retired guardrail", "Executive / architect", "Value stream map", "End to end",
  [G("1 Propose", "gry", [N("a1", "Risk or audit finding|trigger", "user", "RSK"), N("a2", "RFC + ADR|options, reversibility", "mgmt", "ADR")]),
   G("2 Author and test", "aws", [N("b1", "Control definition|one record", "compute", "DEF"), N("b2", "Generate + prove|4 engines, parity", "sec", "GEN")]),
   G("3 Approve", "az", [N("c1", "Peer + security review|PR", "user", "REV"), N("c2", "Board decision|per severity", "user", "ARB")]),
   G("4 Audit mode", "gcp", [N("d1", "Audit / dry-run|all clouds", "mgmt", "AUD"), N("d2", "Impact report|who breaks", "data", "RPT")]),
   G("5 Enforce", "grn", [N("e1", "Deny by wave|canary first", "sec", "DNY"), N("e2", "Monitor + waivers|expiring", "mgmt", "MON")]),
   G("6 Review", "pur", [N("f1", "Quarterly review|false positives", "mgmt", "KPI"), N("f2", "Retire or revise|new ADR", "mgmt", "RET")])],
  [("a2", "b1", "approved scope"), ("b2", "c1", "PR opened"), ("c2", "d1", "release tagged"), ("d2", "e1", "gate: impact accepted"), ("e2", "f1", "metrics"), ("f2", "a1", "new risks", "dash")],
  ["Pain removed: policies written four times by four teams, enforced before anyone knew who they would break."]),

S("c4-container", "C4 container view of the baseline", "Deployable and runnable units, and what flows between them", "Architect / engineer", "C4 level 2", "Policy-as-Code Baseline",
  [G("Policy repository (Git)", "ctl", [N("def", "Control definitions|source of truth", "storage", "DEF"), N("gen", "Generator|build_policies.py", "compute", "GEN"), N("art", "Generated artifacts|Rego, SCP, Policy, OrgPol", "storage", "ART"), N("man", "Manifest|fidelity + files", "storage", "MAN")], cols=2),
   G("Quality gates", "aws", [N("orc", "Python oracle|79 fixtures", "compute", "ORC"), N("opa", "OPA tests|generated", "compute", "OPA"), N("par", "Parity gate|verify_parity.py", "sec", "PAR"), N("pln", "Plan evaluator|evaluate_plan.py", "compute", "PLN")], cols=2),
   G("Release and deploy", "az", [N("reg", "Policy registry|signed bundles", "storage", "REG"), N("dep", "Deployer|Terraform + OIDC", "compute", "TF"), N("exs", "Exception service|waivers + expiry", "compute", "EXC")]),
   G("Assurance", "gcp", [N("col", "Compliance collector|3 clouds", "compute", "COL"), N("ev", "Evidence store|immutable", "storage", "EVD"), N("dash", "Scorecard|dashboards", "data", "DSH")])],
  [("def", "gen", "read"), ("gen", "art", "emit"), ("gen", "man", "emit"), ("art", "orc", "fixtures"), ("art", "opa", "rego + tests"), ("man", "par", "verify 1:1"), ("par", "reg", "pass: publish", "ok"), ("pln", "reg", "plan rules"),
   ("reg", "dep", "pull bundle"), ("exs", "dep", "active waivers"), ("dep", "col", "deployed state", "dash"), ("col", "ev", "snapshots"), ("col", "dash", "scores")]),

matrix("part-1", ["PAC-001", "PAC-002", "PAC-003", "PAC-004", "PAC-005", "PAC-006"], 1),
matrix("part-2", ["PAC-007", "PAC-008", "PAC-009", "PAC-010", "PAC-011", "PAC-012"], 2),

S("defense-in-depth", "Four-layer enforcement architecture", "Where each engine sits between a developer's keyboard and a running resource", "Architect / security", "Layered controls", "Prevent, detect, respond",
  [G("1 Author time", "gry", [N("ide", "IDE + pre-commit|conftest, tflint", "compute", "IDE"), N("pr", "Pull request|plan comment", "user", "PR")]),
   G("2 Pipeline gate", "ctl", [N("plan", "terraform plan|JSON", "compute", "TF"), N("opa", "OPA / Conftest|12 packages", "sec", "OPA"), N("gate", "Required check|blocks merge", "sec", "GATE")]),
   G("3 Cloud control plane", "sec", [N("scp", "AWS SCP|deny at API", "sec", "SCP"), N("pol", "Azure Policy|deny / modify", "az", "POL"), N("orgp", "GCP Org Policy|constraints", "gcp", "ORG")], style="tb"),
   G("4 Runtime detective", "aws", [N("cfg", "AWS Config|rules", "mgmt", "CFG"), N("apc", "Azure compliance|policy insights", "az", "AZ"), N("scc", "GCP SCC + CAI|findings", "gcp", "SCC")]),
   G("5 Response", "grn", [N("tk", "Ticket + owner|SLA", "int", "TKT"), N("rem", "Approved remediation|automation", "compute", "FIX")])],
  [("ide", "pr", "push"), ("pr", "plan", "CI starts"), ("plan", "opa", "plan JSON"), ("opa", "gate", "violations"), ("gate", "pr", "fail: blocked", "red"), ("gate", "scp", "merge + apply", "ok"), ("gate", "pol", "merge + apply", "ok"),
   ("gate", "orgp", "merge + apply", "ok"), ("scp", "cfg", "gaps remain", "dash"), ("pol", "apc", "compliance", "dash"), ("orgp", "scc", "findings", "dash"), ("cfg", "tk", "non-compliant", "dash"), ("tk", "rem", "approved fix")],
  ["No single layer is trusted: SCPs and Org Policy cannot see every attribute, so the Rego gate and detective layer cover the gaps (ADR-0002)."]),

S("aws-reference", "AWS reference architecture (live deployment)", "SCP hierarchy, canary OU, break-glass, detective Config and evidence archive", "Engineer / auditor", "AWS-style", "AWS Organization",
  [G("Management account", "aws", [N("org", "AWS Organizations|root + OUs", "mgmt", "ORG"), N("scpn", "SCP set|PAC controls", "sec", "SCP"), N("ou", "OU design|Sandbox, NonProd, Prod", "mgmt", "OU")]),
   G("Policy canary OU", "aws", [N("tacc", "Canary account|synthetic workloads", "compute", "ACC"), N("tcfg", "Config rules|detective", "mgmt", "CFG")]),
   G("Workload OUs", "aws", [N("prod", "Prod accounts|SCP enforced", "compute", "PRD"), N("np", "NonProd accounts|SCP enforced", "compute", "NP"), N("bg", "pac-platform-admin|break-glass, MFA", "sec", "IAM")]),
   G("Security tooling account", "aws", [N("agg", "Config aggregator|org-wide", "mgmt", "AGG"), N("sh", "Security Hub|findings", "sec", "SH"), N("eb", "EventBridge|policy changes", "int", "EB"), N("ddb", "Compliance store|DynamoDB", "db", "DDB")], cols=2),
   G("Log archive account", "aws", [N("ct", "Org CloudTrail|all regions", "mgmt", "CT"), N("s3", "Evidence bucket|S3 Object Lock", "storage", "S3")]),
   G("Policy pipeline account", "aws", [N("run", "Pipeline runner|GitHub OIDC", "compute", "CI"), N("role", "Policy deploy role|organizations:*Policy", "sec", "IAM")])],
  [("run", "role", "assume"), ("role", "scpn", "put + attach", "ok"), ("scpn", "ou", "inherits down"), ("ou", "tacc", "canary first"), ("ou", "prod", "then waves"), ("scpn", "prod", "deny at API", "red"), ("bg", "prod", "bypass: alarmed", "red"),
   ("tcfg", "agg", "compliance", "dash"), ("prod", "agg", "compliance", "dash"), ("agg", "sh", "findings"), ("agg", "ddb", "snapshots"), ("ct", "eb", "policy API calls", "dash"), ("eb", "ddb", "change record"), ("ct", "s3", "log files")],
  ["SCPs have no audit mode: the canary OU plus Config rules is the dry-run equivalent on AWS (ADR-0005)."]),

S("azure-reference", "Azure reference architecture (live deployment)", "Management-group hierarchy, initiative assignments, exemptions and remediation identities", "Engineer / auditor", "Azure-style on AWS notation", "Azure tenant",
  [G("Management groups", "az", [N("root", "Tenant root group|no assignments", "az", "MG"), N("plat", "Platform MG|connectivity, identity", "az", "MG"), N("lz", "Landing zones MG|workloads", "az", "MG"), N("sbx", "Sandbox MG|canary scope", "az", "MG")]),
   G("Policy plane", "az", [N("defs", "Definitions|PAC-001 to 012", "sec", "POL"), N("init", "Initiative|PaC baseline v1", "sec", "INI"), N("asg", "Assignments|effect parameter", "sec", "ASG"), N("exm", "Exemptions|expiresOn", "mgmt", "EXM")], cols=2),
   G("Remediation", "az", [N("mi", "Policy identity|managed identity", "sec", "MI"), N("rt", "Remediation tasks|modify, DINE", "compute", "RT")]),
   G("Assurance", "az", [N("pi", "Policy insights|compliance state", "mgmt", "PI"), N("arg", "Resource Graph|queries", "mgmt", "ARG"), N("la", "Log Analytics|activity log", "mgmt", "LA"), N("dfc", "Defender for Cloud|regulatory view", "sec", "DFC")]),
   G("Pipeline", "az", [N("ci", "GitHub Actions|federated credential", "compute", "CI"), N("sp", "Deployer identity|Resource Policy Contributor", "sec", "SP")])],
  [("ci", "sp", "federate"), ("sp", "defs", "deploy", "ok"), ("defs", "init", "grouped"), ("init", "asg", "assign"), ("asg", "sbx", "audit first", "dash"), ("asg", "lz", "then Deny", "red"), ("exm", "asg", "time-boxed"), ("asg", "mi", "needs identity"),
   ("mi", "rt", "executes"), ("lz", "pi", "evaluates", "dash"), ("pi", "arg", "query"), ("lz", "la", "activity log", "dash"), ("la", "dfc", "alerts", "dash")],
  ["Policy exemptions are first-class and expire; this is the Azure answer to waivers (see exception diagram 15)."]),

S("gcp-reference", "GCP reference architecture (live deployment)", "Org Policy with dry-run, custom constraints, policy analysis and audit trail", "Engineer / auditor", "GCP-style on AWS notation", "GCP organization",
  [G("Organization and folders", "gcp", [N("org", "Organization|root", "gcp", "ORG"), N("fold", "Folders|prod, nonprod, sandbox", "gcp", "FLD"), N("pol", "Org Policies|boolean + list", "sec", "POL"), N("cc", "Custom constraints|labels, firewall", "sec", "CEL")]),
   G("Dry-run and enforce", "gcp", [N("dry", "dryRunSpec|audit mode", "mgmt", "DRY"), N("enf", "spec|enforced", "sec", "ENF"), N("tg", "Resource tags|conditional scope", "mgmt", "TAG")]),
   G("Workloads", "gcp", [N("prj", "Projects|per workload", "gcp", "PRJ"), N("res", "Resources|GCE, GCS, SQL", "compute", "GCE")]),
   G("Assurance", "gcp", [N("cai", "Cloud Asset Inventory|org feed", "mgmt", "CAI"), N("pa", "Policy Analyzer|what-if", "mgmt", "PA"), N("scc", "Security Command Center|findings", "sec", "SCC"), N("log", "Audit logs|policy changes", "mgmt", "LOG")], cols=2),
   G("Pipeline", "gcp", [N("ci", "GitHub Actions|WIF", "compute", "CI"), N("sa", "Org policy admin SA|impersonated", "sec", "SA")])],
  [("ci", "sa", "federate"), ("sa", "pol", "set policy", "ok"), ("cc", "pol", "referenced by"), ("pol", "dry", "audit first", "dash"), ("dry", "enf", "promote", "ok"), ("fold", "prj", "inherits"), ("enf", "res", "deny at API", "red"),
   ("tg", "enf", "scoped exceptions"), ("res", "cai", "inventory", "dash"), ("cai", "pa", "analyze"), ("cai", "scc", "violations", "dash"), ("pol", "log", "audit trail", "dash")],
  ["dryRunSpec lets a constraint log would-be violations without blocking: GCP's native audit mode."]),

S("hierarchy-mapping", "Scope hierarchy mapping across clouds", "Where a policy attaches, and how inheritance behaves at each level", "Architect", "Mapping matrix", "Attachment points",
  [G("Neutral scope", "ctl", [N("n1", "Organization|everything", "mgmt", "ORG"), N("n2", "Business unit|OU, MG, folder", "mgmt", "BU"), N("n3", "Workload|account, sub, project", "mgmt", "WL"), N("n4", "Resource|object level", "mgmt", "RES")]),
   G("AWS", "aws", [N("a1", "Org root|SCP attach", "compute", "ROOT"), N("a2", "OU|SCP attach, inherits", "compute", "OU"), N("a3", "Account|SCP attach, rare", "compute", "ACC"), N("a4", "Resource|condition keys", "compute", "RES")]),
   G("Azure", "az", [N("z1", "Tenant root MG|avoid assigns", "az", "MG"), N("z2", "Management group|assign, inherits", "az", "MG"), N("z3", "Subscription|assign, exempt", "az", "SUB"), N("z4", "Resource group|assign, exempt", "az", "RG")]),
   G("GCP", "gcp", [N("g1", "Organization|policy root", "gcp", "ORG"), N("g2", "Folder|policy, inherits", "gcp", "FLD"), N("g3", "Project|policy, override", "gcp", "PRJ"), N("g4", "Resource|tags, labels", "gcp", "RES")])],
  [("a1", "a2", "inherits"), ("a2", "a3", "inherits"), ("z1", "z2", "inherits"), ("z2", "z3", "inherits"), ("g1", "g2", "inherits"), ("g2", "g3", "inherits")],
  ["Rule of thumb: attach at the business-unit level, exempt at workload level, never at the root. Child policies can only tighten AWS SCPs, but Azure and GCP allow overrides."], rowlink=True),

S("release-pipeline", "Policy release pipeline with gates", "From pull request to signed, staged, evidenced rollout", "Engineer / auditor", "Pipeline", "GitHub Actions",
  [G("Author", "gry", [N("pr", "Pull request|conventional commits", "user", "PR"), N("rv", "Code owners review|security + CoE", "user", "REV")]),
   G("Generate and test", "ctl", [N("gen", "Generate artifacts|from definitions", "compute", "GEN"), N("orc", "Python oracle|79 fixtures", "compute", "ORC"), N("opa", "opa test|generated rego tests", "sec", "OPA"), N("par", "Parity gate|4 engines per control", "sec", "PAR")], cols=2),
   G("Validate against reality", "aws", [N("tfv", "terraform validate|3 modules", "compute", "TF"), N("snap", "Plan snapshot tests|sample plans", "compute", "PLN"), N("imp", "Impact simulation|inventory what-if", "data", "SIM")]),
   G("Release", "grn", [N("sig", "Sign + SBOM|cosign", "sec", "SIG"), N("rel", "Tag release|semver + notes", "mgmt", "REL"), N("reg", "Policy registry|bundle", "storage", "REG")]),
   G("Promote", "az", [N("can", "Canary scope|per cloud", "compute", "CAN"), N("wave", "Wave rollout|audit then enforce", "compute", "WAV"), N("evd", "Evidence pack|attached to release", "storage", "EVD")])],
  [("pr", "rv", "review"), ("rv", "gen", "merge queue"), ("gen", "orc", "fixtures"), ("gen", "opa", "rego"), ("orc", "par", "pass"), ("opa", "par", "pass"), ("par", "tfv", "1:1 proven", "ok"), ("tfv", "snap", "pass"), ("snap", "imp", "pass"),
   ("imp", "sig", "impact accepted", "ok"), ("sig", "rel", "artifacts"), ("rel", "reg", "publish"), ("reg", "can", "deploy", "ok"), ("can", "wave", "gate"), ("wave", "evd", "record", "dash")]),

S("enforcement-modes", "Enforcement mode ladder", "How one control moves from draft to deny, and what 'audit' means on each cloud", "Architect / SRE", "State machine", "Rollout",
  [G("Draft", "gry", [N("d1", "Proposed|RFC + ADR", "user", "RFC")]),
   G("Audit (no blocking)", "aws", [N("au1", "AWS: canary OU|SCP + Config rule", "compute", "AWS"), N("au2", "Azure: effect=Audit|compliance only", "az", "AZ"), N("au3", "GCP: dryRunSpec|logs violations", "gcp", "GCP")]),
   G("Warn", "az", [N("w1", "PR check warns|non-blocking", "mgmt", "WRN"), N("w2", "Owners notified|SLA clock", "int", "NTF")]),
   G("Enforce", "sec", [N("e1", "AWS: SCP attached|OU by OU", "sec", "SCP"), N("e2", "Azure: effect=Deny|per MG", "sec", "DNY"), N("e3", "GCP: spec enforced|folder by folder", "sec", "ENF")], style="tb"),
   G("Retire", "pur", [N("r1", "Deprecate|notice period", "mgmt", "DEP"), N("r2", "Detach + archive|evidence kept", "storage", "ARC")])],
  [("d1", "au1", "approved"), ("d1", "au2", "approved"), ("d1", "au3", "approved"), ("au2", "w1", "gate: impact accepted"), ("w1", "w2", "30 days"), ("w2", "e1", "gate: zero criticals", "ok"), ("w2", "e2", "gate: zero criticals", "ok"),
   ("w2", "e3", "gate: zero criticals", "ok"), ("e2", "au2", "rollback: effect=Audit", "red"), ("e1", "r1", "superseded", "dash")],
  ["AWS SCPs have no native audit mode, so audit means the canary OU plus Config; Azure uses an effect parameter; GCP uses dryRunSpec."]),

S("ci-decision-flow", "CI decision flow for a Terraform change", "What happens to a pull request, including the failure and override paths", "Developer / engineer", "Flow", "Pipeline gate",
  [G("Developer", "gry", [N("dev", "Engineer|changes IaC", "user", "DEV"), N("pr", "Pull request|opened", "user", "PR")]),
   G("CI", "ctl", [N("plan", "terraform plan|JSON output", "compute", "TF"), N("opa", "Conftest|12 packages", "sec", "OPA"), N("rep", "Report|PR comment", "mgmt", "RPT")]),
   G("Policy inputs", "aws", [N("bun", "Policy bundle|pinned version", "storage", "REG"), N("wv", "Waiver lookup|active exceptions", "db", "EXC")]),
   G("Outcomes", "grn", [N("ok", "Merge allowed|all green", "mgmt", "OK"), N("no", "Merge blocked|violations listed", "sec", "FAIL"), N("ov", "Break-glass override|two approvers", "user", "OVR")])],
  [("dev", "pr", "push"), ("pr", "plan", "trigger"), ("plan", "opa", "plan JSON"), ("bun", "opa", "rules"), ("wv", "opa", "waivers apply"), ("opa", "rep", "results"), ("rep", "ok", "no violations", "ok"), ("rep", "no", "violations", "red"),
   ("no", "dev", "fix and push", "red"), ("no", "ov", "urgent only", "dash"), ("ov", "ok", "logged + reviewed", "dash")],
  ["Overrides are audited, expire in 24 hours and are reviewed within two business days (docs/12-governance)."]),

S("exception-workflow", "Exception and waiver workflow", "One request, three native implementations, one expiry clock", "Security / GRC", "Process flow", "Exceptions",
  [G("Request", "gry", [N("req", "Request|owner, reason, expiry", "user", "REQ"), N("tk", "Ticket|ServiceNow", "ext", "SN")]),
   G("Review", "ctl", [N("risk", "Risk review|security", "user", "RSK"), N("arb", "Board decision|by severity", "user", "ARB")]),
   G("Implement", "az", [N("aws", "AWS: scoped SCP condition|principal or OU", "compute", "AWS"), N("az", "Azure: policy exemption|expiresOn", "az", "AZ"), N("gcp", "GCP: scoped override|folder or tag", "gcp", "GCP")]),
   G("Control", "grn", [N("reg", "Exception register|Git + database", "storage", "REG"), N("exp", "Expiry sweeper|7-day notice", "compute", "EXP"), N("rec", "Recertify or remove|owner", "user", "OWN")])],
  [("req", "tk", "file"), ("tk", "risk", "assess"), ("risk", "arb", "high severity only"), ("arb", "aws", "approved", "ok"), ("arb", "az", "approved", "ok"), ("arb", "gcp", "approved", "ok"), ("aws", "reg", "recorded", "dash"),
   ("az", "reg", "recorded", "dash"), ("gcp", "reg", "recorded", "dash"), ("reg", "exp", "daily scan"), ("exp", "rec", "7 days before expiry"), ("rec", "reg", "renew once or remove", "dash")],
  ["Maximum 90 days, renewable once. An exception that cannot be removed becomes a policy change (new ADR)."]),

S("identity-trust", "Identity and separation of duties", "Who can change guardrails, and how pipelines authenticate without keys", "Security", "Identity flow", "Trust relationships",
  [G("GitHub", "gry", [N("pr", "Pull request|author cannot approve", "user", "PR"), N("env", "Protected environment|two reviewers", "user", "ENV"), N("oidc", "OIDC token|short-lived", "ext", "OIDC")]),
   G("AWS", "aws", [N("sts", "STS|AssumeRoleWithWebIdentity", "sec", "STS"), N("adm", "Policy deploy role|policy APIs only", "sec", "IAM"), N("bg", "pac-platform-admin|break-glass + MFA", "sec", "BG")]),
   G("Azure", "az", [N("fic", "Federated credential|environment subject", "az", "FIC"), N("sp", "Deployer identity|Resource Policy Contributor", "sec", "SP")]),
   G("GCP", "gcp", [N("wif", "Workload identity pool|GitHub provider", "sec", "WIF"), N("sa", "Org policy admin SA|impersonated", "sec", "SA")])],
  [("pr", "env", "merge to main"), ("env", "oidc", "approved run"), ("oidc", "sts", "token"), ("oidc", "fic", "token"), ("oidc", "wif", "token"), ("sts", "adm", "assume", "ok"), ("fic", "sp", "federate", "ok"), ("wif", "sa", "impersonate", "ok"), ("bg", "adm", "emergency only", "red")],
  ["No long-lived keys anywhere (this baseline enforces its own PAC-006). Policy authors never hold deploy permissions."]),

S("threat-model", "Threat model (STRIDE) for the policy plane", "Attacks on the guardrails themselves, and the control answering each", "Security / architect", "STRIDE + data flow", "Policy plane",
  [G("Threats", "sec", [N("t1", "T1 Weaken a policy|malicious PR", "ext", "T"), N("t2", "T2 Bypass via admin|break-glass abuse", "ext", "E"), N("t3", "T3 Detach guardrail|API call", "ext", "T"), N("t4", "T4 Stale exemption|never expires", "ext", "R"), N("t5", "T5 Pipeline credential theft|token abuse", "ext", "S")]),
   G("Targets", "aws", [N("repo", "Policy repository", "storage", "GIT"), N("adm", "Admin roles", "sec", "IAM"), N("att", "Policy attachments", "sec", "POL"), N("exr", "Exception register", "storage", "EXC"), N("pipe", "Release pipeline", "compute", "CI")], cols=2),
   G("Mitigations", "grn", [N("m1", "Code owners + parity gate|2 reviewers", "sec", "REV"), N("m2", "MFA + alarm + review|24h expiry", "sec", "BG"), N("m3", "Org-level deny|guards policy APIs", "sec", "SCP"), N("m4", "Expiry sweeper|forced removal", "compute", "EXP"), N("m5", "OIDC, env approval|no stored keys", "sec", "OIDC")])],
  [("t1", "repo", "targets", "red"), ("t2", "adm", "targets", "red"), ("t3", "att", "targets", "red"), ("t4", "exr", "targets", "red"), ("t5", "pipe", "targets", "red"), ("repo", "m1", "protected by", "ok"), ("adm", "m2", "protected by", "ok"),
   ("att", "m3", "protected by", "ok"), ("exr", "m4", "protected by", "ok"), ("pipe", "m5", "protected by", "ok")],
  ["Residual: an organization owner can still remove any control. Detective alarms on policy-API calls make it visible within minutes (risk R-04)."]),

S("assurance-loop", "Assurance and drift loop", "Measuring whether deployed policy still matches intended policy", "SRE / GRC", "Data flow", "Detect and report",
  [G("Native compliance sources", "gry", [N("cfg", "AWS Config|aggregator", "mgmt", "CFG"), N("azp", "Azure Policy insights|compliance", "az", "AZ"), N("gcc", "GCP Asset + SCC|findings", "gcp", "GCP")]),
   G("Normalize", "ctl", [N("col", "Collector|neutral record", "compute", "COL"), N("map", "Control mapper|PAC id + engine", "compute", "MAP"), N("dr", "Drift check|deployed vs intended", "sec", "DRF")]),
   G("Store", "aws", [N("lake", "Compliance lake|S3 + Athena", "storage", "LAKE"), N("ev", "Evidence store|WORM", "storage", "S3")]),
   G("Act", "grn", [N("sc", "Scorecard|by control + cloud", "data", "SCR"), N("tk", "Tickets|owners", "int", "TKT"), N("ex", "Waiver expiry|auto sweep", "compute", "EXP")])],
  [("cfg", "col", "compliance", "dash"), ("azp", "col", "compliance", "dash"), ("gcc", "col", "findings", "dash"), ("col", "map", "records"), ("map", "dr", "mapped"), ("dr", "lake", "deltas"), ("dr", "ev", "snapshots", "dash"),
   ("lake", "sc", "query"), ("lake", "tk", "violations", "dash"), ("lake", "ex", "expiring waivers"), ("sc", "tk", "SLA breach", "red")]),

S("evidence-architecture", "Evidence and audit architecture", "How a control becomes audit evidence without manual collection", "Audit / GRC", "Traceability", "Assurance",
  [G("Controls", "ctl", [N("c1", "PAC controls|12", "mgmt", "PAC"), N("c2", "Fidelity + gaps|honest mapping", "mgmt", "FID")]),
   G("Frameworks", "pur", [N("f1", "NIST 800-53", "ext", "NIST"), N("f2", "CIS Controls v8", "ext", "CIS"), N("f3", "ISO 27001:2022", "ext", "ISO"), N("f4", "SOC 2", "ext", "SOC")]),
   G("Evidence sources", "aws", [N("e1", "Policy files|in Git, signed", "storage", "GIT"), N("e2", "Test results|oracle + OPA", "storage", "TST"), N("e3", "Compliance snapshots|daily", "storage", "SNP"), N("e4", "Change records|PRs + approvals", "storage", "CHG")]),
   G("Audit pack", "grn", [N("b", "Pack builder|per framework", "compute", "BLD"), N("ap", "Auditor view|read-only", "user", "AUD")])],
  [("c1", "f1", "satisfies"), ("c1", "f2", "satisfies"), ("c1", "f3", "satisfies"), ("c2", "f4", "limits stated"), ("f1", "e1", "evidence"), ("f2", "e2", "evidence"), ("f3", "e3", "evidence"), ("f4", "e4", "evidence"),
   ("e1", "b", "collect", "dash"), ("e3", "b", "collect", "dash"), ("b", "ap", "publish", "ok")]),

S("roadmap-waves", "Rollout roadmap with funding gates", "Audit first, enforce later: every wave gated by evidence", "Executive / PMO", "Roadmap", "Transformation",
  [G("Wave 0: Foundation", "gry", [N("w0a", "Catalogue + generator|12 controls", "mgmt", "CAT"), N("w0b", "Sandbox scopes|1 per cloud", "compute", "SBX")]),
   G("Wave 1: Audit everywhere", "aws", [N("w1a", "Audit mode on|all 12 controls", "mgmt", "AUD"), N("w1b", "Baseline impact report|who breaks", "data", "RPT")]),
   G("Wave 2: Enforce non-prod", "az", [N("w2a", "Deny in NonProd|per cloud", "sec", "DNY"), N("w2b", "Waiver process live|ServiceNow", "int", "EXC")]),
   G("Wave 3: Enforce prod", "gcp", [N("w3a", "Deny in Prod|change windows", "sec", "DNY"), N("w3b", "Break-glass tested|drill", "sec", "BG")]),
   G("Wave 4: Continuous", "grn", [N("w4a", "Quarterly policy review|ADR driven", "mgmt", "REV"), N("w4b", "Evidence automation|audit packs", "storage", "EVD")]),
   G("Governance", "ctl", [N("gov", "Policy board|monthly", "user", "BRD"), N("gate", "Exit criteria|evidence pack", "mgmt", "GATE")])],
  [("w0b", "w1a", "gate 1"), ("w1b", "w2a", "gate 2"), ("w2b", "w3a", "gate 3"), ("w3b", "w4a", "gate 4"), ("gov", "gate", "reviews"), ("gate", "w1a", "approves", "ok")],
  ["Gate criteria: zero unreviewed criticals in audit, rollback tested, owner coverage >= 95% before any deny is enabled."]),
]
assert len(SPECS) == 20, len(SPECS)
