"""Run the three experiments and print the results in the terminal.
Usage:  python demo.py to get the terminal ouputs to see the different test pass 
"""

import os
import sys

from blocksig.experiments import run_all


def print_experiment(exp):
    print("\n" + "=" * 72)
    print(f"Experiment {exp['id']}: {exp['title']}")
    print("=" * 72)
    for step in exp["steps"]:
        if step["kind"] == "info":
            print(f"  {step['text']}")
        elif step["kind"] == "data":
            print(f"    {step['label']}: {step['value']}")
        elif step["kind"] == "outcome":
            print(f"  {step['text']} -> {step['status']} ({step['detail']})"
                  f"   [{'PASS' if step['ok'] else 'FAIL'}]")
        else:
            print(f"  [{'PASS' if step['ok'] else 'FAIL'}] {step['text']}")


def main():
    exps = run_all()
    for exp in exps:
        print_experiment(exp)
    passed = sum(e["passed"] for e in exps)
    total = sum(e["total"] for e in exps)
    print("\n" + "=" * 72)
    print(f"SUMMARY: {passed}/{total} checks passed")

    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", "demo_results.md"), "w") as f:
        f.write("| Experiment | Check | Result |\n|---|---|---|\n")
        for e in exps:
            for s in e["steps"]:
                if s["kind"] == "check":
                    f.write(f"| {e['id']} | {s['text']} | {'PASS' if s['ok'] else 'FAIL'} |\n")
                elif s["kind"] == "outcome":
                    f.write(f"| {e['id']} | {s['text']} ({s['detail']}): {s['status']} | {'PASS' if s['ok'] else 'FAIL'} |\n")
    print("Results table written to results/demo_results.md")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()