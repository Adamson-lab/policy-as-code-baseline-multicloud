#!/usr/bin/env python3
"""Structural 1:1 parity gate: every control exists in all four engines, files parse, native limits respected. Exit 1 on any failure."""
import json, os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(p):
    return json.load(open(os.path.join(ROOT, p), encoding="utf-8"))


def verify():
    errs, man = [], load("controls/manifest.json")
    for m in man:
        cid = m["id"]
        for k in ("rego", "rego_test", "aws", "azure", "gcp"):
            if k not in m["files"] or not os.path.exists(os.path.join(ROOT, m["files"][k])):
                errs.append(f"{cid}: missing {k} artifact")
        if errs and errs[-1].startswith(cid):
            continue
        rg = open(os.path.join(ROOT, m["files"]["rego"]), encoding="utf-8").read()
        if cid not in rg or rg.count("deny contains") < m["rego_rules"]:
            errs.append(f"{cid}: rego rule count below definition")
        for e, d in m["engines"].items():
            if d["fidelity"] not in ("full", "partial", "compensating"):
                errs.append(f"{cid}/{e}: bad fidelity")
            if d["fidelity"] != "full" and not d["gap"]:
                errs.append(f"{cid}/{e}: non-full mapping needs a documented gap")
        a = load(m["files"]["aws"])
        if m["engines"]["aws"]["kind"] == "preventive":
            if len(json.dumps(a, separators=(",", ":"))) > 5120:
                errs.append(f"{cid}: SCP exceeds 5120 chars")
            for s in a["Statement"]:
                if s["Effect"] != "Deny" or not s["Sid"].startswith(cid.replace("-", "")):
                    errs.append(f"{cid}: SCP statement must be Deny with Sid prefixed by control id")
        elif "Source" not in a:
            errs.append(f"{cid}: Config rule missing Source")
        z = load(m["files"]["azure"])["properties"]
        if z["metadata"]["controlId"] != cid or "if" not in z["policyRule"] or "then" not in z["policyRule"]:
            errs.append(f"{cid}: Azure policy malformed")
        if z["parameters"]["effect"]["defaultValue"] not in z["parameters"]["effect"]["allowedValues"]:
            errs.append(f"{cid}: Azure default effect not allowed")
        g = load(m["files"]["gcp"])
        if m["engines"]["gcp"]["kind"] == "preventive" and not ("spec" in g and g["name"].startswith("organizations/")):
            errs.append(f"{cid}: GCP org policy malformed")
    bund = load("controls/bundles.json")
    covered = {c for b in bund for c in b["controls"]}
    need = {m["id"] for m in man if m["engines"]["aws"]["kind"] == "preventive"}
    if covered != need:
        errs.append(f"SCP bundles do not cover {sorted(need - covered)}")
    if len(bund) > 4:
        errs.append("more than 4 SCP bundles: exceeds AWS per-target limit of 5 with FullAWSAccess")
    if any(b["chars"] > 5120 for b in bund):
        errs.append("SCP bundle exceeds 5120 chars")
    cov = {"controls": len(man), "engines_per_control": 4, "fixtures": sum(m["fixtures"] for m in man), "errors": errs}
    json.dump(cov, open(os.path.join(ROOT, "evidence", "parity-report.json"), "w"), indent=2)
    return cov


if __name__ == "__main__":
    r = verify()
    print(json.dumps({k: v for k, v in r.items() if k != "errors"}), "errors:", len(r["errors"]))
    for e in r["errors"]:
        print(" -", e)
    sys.exit(1 if r["errors"] else 0)
