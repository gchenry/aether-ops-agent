---
name: tests
description: Run the local pytest test suites for aether-ops-agent including SPIFFE/mTLS security tests and LLM evaluations. Use whenever the user asks to run tests, pytests, /tests, or test the agent.
---

# Local Test Runner (`tests`)

Run and analyze the local pytest test suites for `aether-ops-agent`.

## Test Execution

Execute the project's tests via the runner script, Antigravity CLI, or pytest:

```bash
./run_tests.sh [security|evals|all]
```

### Execution Methods:
- **Via Runner Script**:
  - `./run_tests.sh security` (~11s, 13 SPIFFE/mTLS/ABAC/OWASP ASI tests)
  - `./run_tests.sh evals` (~35s, 2 Gemini-as-a-Judge evaluations)
  - `./run_tests.sh all` (Runs all 15 tests)
- **Via Antigravity CLI**:
  - `agy tests [security|evals|all]`
- **Via Slash Command**:
  - `/tests`
- **Via Pytest Directly**:
  - `.venv/bin/pytest tests/test_security.py`
  - `.venv/bin/pytest tests/test_agent_evals.py`
  - `.venv/bin/pytest -k <keyword>`

## Verification
Inspect the test output, verify all test cases pass, and summarize any assertions, HTTP status mismatches, or SPIFFE/mTLS failures.
