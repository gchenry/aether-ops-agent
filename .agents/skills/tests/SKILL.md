---
name: tests
description: Run the local pytest test suites (.venv/bin/pytest) for aether-ops-agent including SPIFFE/mTLS security tests and LLM evaluations. Use whenever the user asks to run tests, pytests, /tests, or test the agent.
---

# Local Test Suite Runner (`tests`)

Run and analyze the local pytest test suites for `aether-ops-agent` from the command line.

## Test Execution

Execute the project's tests using the local virtual environment:

```bash
.venv/bin/pytest "$@"
```

### Common Targets:
- **Fast Security Tests Only** (~11s, 13 SPIFFE/mTLS/ABAC/OWASP ASI tests):
  ```bash
  .venv/bin/pytest tests/test_security.py
  ```
- **Gemini LLM-as-a-Judge Evaluation Tests** (~35s):
  ```bash
  .venv/bin/pytest tests/test_agent_evals.py
  ```
- **Full Test Suite** (~44s, all 15 tests):
  ```bash
  .venv/bin/pytest
  ```
- **Filter by Keyword / Expression**:
  ```bash
  .venv/bin/pytest -k <keyword>
  ```

## Slash Command
Within Antigravity IDE or chat sessions, invoke with `/tests`.

## Verification
Inspect the test output, verify all test cases pass, and summarize any assertions, HTTP status mismatches, or SPIFFE/mTLS failures.
