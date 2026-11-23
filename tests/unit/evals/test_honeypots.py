import pytest

import tests.unit.evals.support.test_honeypots_given as given
import tests.unit.evals.support.test_honeypots_then as then
from evals.honeypots import audit_honeypots


async def test_auditing_the_honeypots_merges_their_reports():
    reports = given.a_report_per_honeypot()

    verdicts, merged = await audit_honeypots(reports.audit)

    then.merged(verdicts, merged, list(reports.by_honeypot.values()))


async def test_auditing_the_honeypots_merges_in_a_fixed_order_whatever_finishes_first():
    reverse = given.a_report_per_honeypot_finishing_in_reverse()

    verdicts, merged = await audit_honeypots(reverse.audit)

    then.merged(verdicts, merged, list(reverse.reports.by_honeypot.values()))


async def test_a_failing_honeypot_cancels_the_other_audits_of_its_run():
    failing = given.OneFailingHoneypot()

    with pytest.raises(given.SubtleHoneypotCrashed):
        await audit_honeypots(failing.audit)

    assert sorted(failing.cancelled) == ["chain_honeypot", "honeypot"]
