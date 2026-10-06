---
name: test
description: Run the local pytest test suites (.venv/bin/pytest) for aether-ops-agent including SPIFFE/mTLS security tests and LLM evaluations. Use whenever the user asks to run tests, pytests, /test, or test the agent.
---

# Local Pytest Runner (`test`)

Run and analyze the local pytest test suites for `aether-ops-agent`.

## Test Execution

Execute the project's tests using the local virtual environment:

```bash
.venv/bin/pytest "$@"
```

### Common Targets:
- **Fast Security Tests Only** (~10s):
  ```bash
  .venv/bin/pytest tests/test_security.py
  ```
- **Gemini LLM-as-a-Judge Evaluation Tests** (~35s):
  ```bash
  .venv/bin/pytest tests/test_agent_evals.py
  ```
- **Full Test Suite**:
  ```bash
  .venv/bin/pytest
  ```
- **Keyword Filter**:
  ```bash
  .venv/bin/pytest -k <keyword>
  ```

## Verification
Inspect the test output, verify all test cases pass, and summarize any assertions, HTTP status mismatches, or SPIFFE/mTLS failures.

