.PHONY: build verify test diagrams plan-ok plan-bad all
build:
	python3 tools/build_policies.py
verify:
	python3 tools/verify_parity.py
test:
	python3 -m unittest discover -s tests -v
diagrams:
	python3 diagrams/src/gen.py
plan-ok:
	python3 tools/evaluate_plan.py examples/plan-compliant.json
plan-bad:
	-python3 tools/evaluate_plan.py examples/plan-noncompliant.json
all: build verify test diagrams
