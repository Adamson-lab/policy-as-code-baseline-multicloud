import json, os, subprocess, sys, unittest
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path[:0] = [os.path.join(ROOT, "controls"), os.path.join(ROOT, "tools")]
from definitions import CONTROLS
import engine, verify_parity


class PolicyTests(unittest.TestCase):
    def test_every_fixture_matches_oracle(self):
        for c in CONTROLS:
            for name, plan, exp in engine.fixtures(c):
                self.assertEqual(len(engine.evaluate(c, plan)), exp, f"{c['id']} {name}")

    def test_every_rule_has_pass_and_fail_fixture(self):
        for c in CONTROLS:
            fx = engine.fixtures(c)
            self.assertTrue(any(e == 0 for _, _, e in fx), c["id"])
            self.assertGreaterEqual(sum(e for _, _, e in fx), len({r["type"] for r in c["tf"]}), c["id"])

    def test_parity_gate_clean(self):
        self.assertEqual(verify_parity.verify()["errors"], [])

    def test_twelve_controls_four_engines(self):
        man = json.load(open(os.path.join(ROOT, "controls", "manifest.json")))
        self.assertEqual(len(man), 12)
        for m in man:
            self.assertEqual(set(m["engines"]), {"aws", "azure", "gcp"})
            self.assertTrue(m["files"]["rego"].endswith(".rego"))

    def test_scp_are_deny_only_and_small(self):
        for f in [x for x in os.listdir(os.path.join(ROOT, "policies", "aws", "scp")) if x.endswith(".json")]:
            doc = json.load(open(os.path.join(ROOT, "policies", "aws", "scp", f)))
            self.assertTrue(all(s["Effect"] == "Deny" for s in doc["Statement"]))
            self.assertLess(len(json.dumps(doc, separators=(",", ":"))), 5120)

    def test_plan_cli_exit_codes(self):
        cli = os.path.join(ROOT, "tools", "evaluate_plan.py")
        ok = subprocess.run([sys.executable, cli, os.path.join(ROOT, "examples", "plan-compliant.json")], capture_output=True, text=True)
        bad = subprocess.run([sys.executable, cli, os.path.join(ROOT, "examples", "plan-noncompliant.json")], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0)
        self.assertEqual(bad.returncode, 1)
        self.assertGreater(len(bad.stdout.splitlines()), 20)

    def test_scp_bundles_respect_aws_limits(self):
        b = json.load(open(os.path.join(ROOT, "controls", "bundles.json")))
        self.assertLessEqual(len(b), 4)
        self.assertTrue(all(x["chars"] <= 5120 for x in b))
        self.assertEqual(sum(len(json.load(open(os.path.join(ROOT, x["file"])))["Statement"]) for x in b), sum(len(c["aws"]["artifact"]["Statement"]) for c in CONTROLS if c["aws"]["kind"] == "preventive"))

    def test_gcp_dryrun_variant_exists_for_org_policies(self):
        man = json.load(open(os.path.join(ROOT, "controls", "manifest.json")))
        for m in man:
            if m["engines"]["gcp"]["kind"] == "preventive":
                self.assertIn("gcp_dryrun", m["files"])


if __name__ == "__main__":
    unittest.main()
