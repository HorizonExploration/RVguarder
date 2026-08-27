"""P0 policy-vector regression tests using the packaged deterministic policy bundle."""

from __future__ import annotations

from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import (
    AuthorizationTrace,
    ContextRef,
    CoverageResult,
    DataRef,
    OperationRef,
    PrincipalRef,
    ResourceRef,
)


POLICY_ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def load_p0_vectors() -> list[dict[str, object]]:
    """Load the real P0 vectors from the bundled permission knowledge base."""
    return PolicyBundle.load(POLICY_ROOT).p0_vectors()


def evaluate_vector(vector: dict[str, object]):
    """Evaluate a vector's declared operation with normalized P0 evidence."""
    operation = str(vector["operation"])
    external = operation == "data.export"
    trace = AuthorizationTrace(
        trace_id=str(vector["id"]),
        principal=PrincipalRef(id="vector-user", type="human", trust="verified"),
        operation=OperationRef(family=operation),
        resource=ResourceRef(
            type="recipient" if external else "document",
            ids=["partner.example"] if external else ["office-doc"],
            scope="external" if external else "workspace",
        ),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="sensitive" if external else "internal", quantity=1),
        context=ContextRef(recipient_zone="external" if external else "internal"),
    )
    return PolicyEvaluator(PolicyBundle.load(POLICY_ROOT)).evaluate(trace)


def test_all_p0_vectors_have_expected_effect():
    """Changing any P0 rule's effective policy outcome must fail its declared vector."""
    for vector in load_p0_vectors():
        assert evaluate_vector(vector).effect == vector["expected_effect"]
