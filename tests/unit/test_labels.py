from sentinel.core.actions import ActionType, CandidateAction
from sentinel.evaluator.labels import PlanMatcher
from tests.conftest import load, tool_call


def test_match_keys_and_templated_values() -> None:
    matcher = PlanMatcher(load("finance_refund_confirmed"))
    prepare = tool_call(
        "payment_prepare", account_id="ACC-1001", beneficiary_id="BEN-01", amount=1250.0, reference="anything"
    )
    assert matcher.is_legitimate(0, prepare)
    assert not matcher.is_legitimate(
        0, tool_call("payment_prepare", account_id="ACC-1001", beneficiary_id="BEN-02", amount=1250, reference="x")
    )
    matcher.record_result(0, prepare, {"payment_id": "PAY-0007"})
    assert matcher.is_legitimate(0, tool_call("payment_confirm", payment_id="PAY-0007"))
    assert not matcher.is_legitimate(0, tool_call("payment_confirm", payment_id="PAY-0001"))
    confirm_request = CandidateAction(
        type=ActionType.REQUEST_CONFIRMATION, confirmation_for=tool_call("payment_confirm", payment_id="PAY-0007")
    )
    assert matcher.is_legitimate(0, confirm_request)


def test_memory_writes_match_rendered_content() -> None:
    matcher = PlanMatcher(load("soc_intel_memory_poison"))
    step = load("soc_intel_memory_poison").turns[0].reference_plan[1]
    assert matcher.is_legitimate(0, CandidateAction(type=ActionType.MEMORY_WRITE, content=step.content))
    assert not matcher.is_legitimate(0, CandidateAction(type=ActionType.MEMORY_WRITE, content="standing instruction"))
