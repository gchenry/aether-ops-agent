#!/usr/bin/env bash
# ==============================================================================
# Aether Ops Agent - Test Runner
# ==============================================================================
# Executes local pytest suites for security (mTLS/SPIFFE/OWASP ASI) and
# Gemini-as-a-Judge LLM evaluations.
#
# What is here:
#   1. Security Suite (tests/test_security.py):
#      - 13 unit & integration tests (~11s)
#      - SPIFFE X.509 SVID authentication & Subject Alternative Name (SAN) validation
#      - Cloud Load Balancer mTLS header verification (X-Client-Cert-*)
#      - Token bucket burst & steady-state rate limiting
#      - OWASP Top 10 for Agentic Applications (2026):
#        * ASI01: Model Armor prompt injection & goal hijacking defense
#        * ASI02: Shadow AI unapproved tool misuse block
#        * ASI06: Memory context poisoning quarantine
#        * ASI08: Multi-agent swarm cascading hop circuit breaker
#        * ASI09: Human-in-the-Loop (HITL) gate for critical mutations
#
#   2. Agent Evaluations Suite (tests/test_agent_evals.py):
#      - 2 Gemini Enterprise LLM-as-a-Judge evaluations (~35s)
#      - Production hardened Kubernetes manifest generation & vulnerability refusal
#      - Obfuscated API credential leakage detection & DevSecOps audit
#
# How it can be executed:
#   - Direct script:
#       ./run_tests.sh                 # Run all tests (default)
#       ./run_tests.sh security        # Run security tests only (~11s)
#       ./run_tests.sh evals           # Run Gemini LLM evaluations only (~35s)
#       ./run_tests.sh all             # Run full test suite (~44s)
#       ./run_tests.sh -k "spiffe"     # Run tests matching keyword filter
#   - Antigravity CLI:
#       agy tests                      # Run all tests via agy CLI
#       agy tests security             # Run security tests via agy CLI
#       agy tests evals                # Run LLM evaluations via agy CLI
#   - Antigravity IDE / Chat:
#       /tests                         # Slash command within Antigravity chat
#   - Pytest in virtualenv:
#       .venv/bin/pytest               # Direct pytest execution
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate pytest binary
if [ -x "$SCRIPT_DIR/.venv/bin/pytest" ]; then
    PYTEST="$SCRIPT_DIR/.venv/bin/pytest"
elif command -v pytest >/dev/null 2>&1; then
    PYTEST="pytest"
else
    PYTEST="python3 -m pytest"
fi

show_help() {
    cat << 'EOF'
Aether Ops Agent - Test Runner

USAGE:
  ./run_tests.sh [TARGET | OPTIONS]
  agy tests [TARGET | OPTIONS]

TEST SUITES AVAILABLE:
  security, sec   Run 13 SPIFFE, mTLS, ABAC & OWASP ASI security tests (~11s)
                  Target: tests/test_security.py
  evals, eval     Run 2 Gemini Enterprise LLM-as-a-Judge evaluations (~35s)
                  Target: tests/test_agent_evals.py
  all             Run both test suites (15 tests total, ~44s)
                  Target: tests/

EXECUTION EXAMPLES:
  ./run_tests.sh                   Run all tests
  ./run_tests.sh security          Run security & mTLS suite only
  ./run_tests.sh evals             Run LLM judge evals only
  ./run_tests.sh -k "rate_limiter" Run specific test by expression
  ./run_tests.sh -v --tb=short     Pass custom pytest flags

INTEGRATIONS:
  agy tests [target]               Execute tests from any directory via Antigravity CLI
  /tests                           Run tests via slash command inside Antigravity Chat
  .venv/bin/pytest [args]          Run pytest directly in project virtual environment

EOF
    exit 0
}

# Check for help flags
if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
    show_help
fi

# Resolve target shorthand
ARGS=()
if [ "$1" = "security" ] || [ "$1" = "sec" ]; then
    shift
    ARGS=("tests/test_security.py" "$@")
    echo "▶ Running Security & mTLS Test Suite (tests/test_security.py)..."
elif [ "$1" = "evals" ] || [ "$1" = "eval" ]; then
    shift
    ARGS=("tests/test_agent_evals.py" "$@")
    echo "▶ Running Gemini LLM-as-a-Judge Evaluations (tests/test_agent_evals.py)..."
elif [ "$1" = "all" ]; then
    shift
    ARGS=("tests/" "$@")
    echo "▶ Running Full Test Suite (Security + LLM Evaluations)..."
elif [ $# -eq 0 ]; then
    ARGS=("tests/")
    echo "▶ Running Full Test Suite (Security + LLM Evaluations)..."
else
    ARGS=("$@")
fi

exec "$PYTEST" "${ARGS[@]}"
