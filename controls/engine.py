"""Reference evaluator (conformance oracle) for the Rego rule DSL, plus fixture generation. Runs without OPA."""
import copy

BAD = object()


def get(after, path):
    cur = after
    for seg in path.split("."):
        if isinstance(cur, list):
            if not seg.isdigit() or int(seg) >= len(cur):
                return False, None
            cur = cur[int(seg)]
        elif isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return False, None
    return cur is not None, cur


def empty(v):
    return v in ("", [], {})


def sat(rule, after):
    found, v = get(after, rule["attr"])
    op, val = rule["op"], rule["val"]
    if op == "forbid":
        return False
    if op == "absent":
        return (not found) or empty(v)
    if op == "ne":
        return (not found) or v != val
    if op == "not_contains":
        return (not found) or val not in v
    if not found:
        return rule["miss"] if op in ("eq", "in") else False
    if op == "eq":
        return v == val
    if op == "in":
        return v in val
    if op == "exists":
        return not empty(v)
    raise ValueError(op)


def evaluate(control, plan):
    """returns list of violation strings for a Terraform plan JSON (resource_changes + configuration)."""
    out = []
    for i, rule in enumerate(control["tf"]):
        if rule["type"].startswith("provider:"):
            cloud = rule["type"].split(":")[1]
            pc = plan.get("configuration", {}).get("provider_config", {}).get(cloud)
            if pc is not None:
                v = pc.get("expressions", {}).get(rule["attr"], {}).get("constant_value")
                if v not in rule["val"]:
                    out.append(f"[{control['id']}] provider {cloud}: {rule['attr']}={v}")
            continue
        for r in plan.get("resource_changes", []):
            if r["type"] != rule["type"] or not set(r["change"]["actions"]) & {"create", "update"}:
                continue
            if not sat(rule, r["change"].get("after") or {}):
                out.append(f"[{control['id']}] {r['address']} ({rule['attr']})")
    return out


def set_path(obj, path, value):
    segs, cur = path.split("."), obj
    for i, s in enumerate(segs):
        last = i == len(segs) - 1
        nxt_list = (not last) and segs[i + 1].isdigit()
        if s.isdigit():
            n = int(s)
            while len(cur) <= n:
                cur.append({} if not last and not nxt_list else None)
            if last:
                cur[n] = value
            else:
                cur[n] = cur[n] if cur[n] is not None else ([] if nxt_list else {})
                cur = cur[n]
        else:
            if last:
                cur[s] = value
            else:
                cur = cur.setdefault(s, [] if nxt_list else {})


def pass_val(rule):
    op, val = rule["op"], rule["val"]
    return {"eq": val, "in": (val[0] if op == "in" else None), "exists": "x", "ne": "10.0.0.0/8", "not_contains": ["10.0.0.0/8"]}.get(op, BAD)


def fail_val(rule):
    op, val = rule["op"], rule["val"]
    if op == "eq":
        return (not val) if isinstance(val, bool) else "invalid"
    return {"in": "invalid-zz", "exists": None, "absent": [{"present": True}], "ne": val, "not_contains": [val]}[op]


def fixtures(control):
    """auto-generated pass/fail plans: yields (name, plan, expected_violations)"""
    out, n = [], 0
    types = list(dict.fromkeys(r["type"] for r in control["tf"]))
    for t in types:
        rules = [r for r in control["tf"] if r["type"] == t]
        if t.startswith("provider:"):
            cloud = t.split(":")[1]
            mk = lambda v: {"configuration": {"provider_config": {cloud: {"expressions": {rules[0]["attr"]: {"constant_value": v}}}}}, "resource_changes": []}
            out.append((f"{t}_pass", mk(rules[0]["val"][0]), 0))
            out.append((f"{t}_fail", mk("zz-invalid-1"), 1))
            continue
        if rules[0]["op"] == "forbid":
            out.append((f"{t}_pass", {"resource_changes": []}, 0))
            out.append((f"{t}_fail", {"resource_changes": [{"address": f"{t}.bad", "type": t, "change": {"actions": ["create"], "after": {"id": "x"}}}]}, 1))
            continue
        base = {}
        for r in rules:
            pv = pass_val(r)
            if r["op"] != "absent":
                set_path(base, r["attr"], pv)
        mk = lambda a: {"resource_changes": [{"address": f"{t}.t", "type": t, "change": {"actions": ["create"], "after": a}}]}
        out.append((f"{t}_pass", mk(base), 0))
        for r in rules:
            a = copy.deepcopy(base)
            fv = fail_val(r)
            if fv is None:
                a.pop(r["attr"].split(".")[0], None) if "." not in r["attr"] else set_path(a, r["attr"], None)
            else:
                set_path(a, r["attr"], fv)
            n += 1
            out.append((f"{t}_{r['attr'].replace('.', '_').replace('-', '_')}_{r['op']}_{r['val'] if isinstance(r['val'], str) else n}".replace("/", "_").replace("*", "star").replace(" ", "_")[:70], mk(a), 1))
    return out
