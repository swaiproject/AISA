"""AISA demo 0.1: offline scripted control checks, never hosted inference."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from uuid import uuid4


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.home() / 'AISA-controlled-demo')
    parser.add_argument('--case', choices=['permitted', 'blocked', 'review', 'missing'], default='permitted')
    parser.add_argument('--task', default='Read the artificial report fixture.')
    args = parser.parse_args()
    if not 1 <= len(args.task) <= 4096:
        parser.error('task must contain 1–4096 characters')
    root = args.workspace.resolve()
    source = root / 'source/baseline-src'
    sys.path.insert(0, str(source))
    from shadow_poc.configuration import TrustedConfiguration
    from shadow_poc.controller import AgentController
    from shadow_poc.contracts import RunContext
    from shadow_poc.capability_broker import CapabilityBroker
    from shadow_poc.evidence_store import AppendOnlyEvidenceStore
    from shadow_poc.shadow_adapter import ScriptedShadowAdapter, ShadowResult
    from shadow_poc.wrappers import InMemoryResourceWrapper, WrapperResult
    from shadow_poc.errors import ContractError

    class StrictFixtureWrapper(InMemoryResourceWrapper):
        wrapper_id = 'aisa-demo-strict-read-v1'

        def execute(self, token, action, broker, decision_epoch):
            status = broker.begin(token, action, self.wrapper_id, decision_epoch)
            if status != 'ACTIVE':
                return WrapperResult(status, None)
            try:
                if action.capability != 'read_file' or dict(action.parameters) != {'encoding': 'utf-8'}:
                    raise ContractError('DEMO_READ_ONLY')
                if action.target not in self.resources:
                    raise ContractError('FIXTURE_MISSING')
                value = self.resources[action.target]
                if not isinstance(value, str) or len(value.encode('utf-8')) > 16384:
                    raise ContractError('FIXTURE_INVALID')
                status = broker.authorize_effect(token)
                if status != 'ACTIVE':
                    return WrapperResult(status, None)
                broker.complete(token)
                return WrapperResult('EXECUTED', value, ('DEMO_IN_MEMORY_FIXTURE',))
            except Exception:
                broker.revoke(token.token_id)
                raise

    assets = root / 'source/controller-assets'
    config = TrustedConfiguration.load(assets, root / 'config/objective.json', root / 'config/policy.json')
    report = 'fixture://public/report.txt'
    review = 'fixture://public/report-for-review.txt'
    text = 'Artificial report: 12 orders received; 10 shipped; 2 pending.'
    resources = {report: text, review: text}
    target = {'permitted': report, 'blocked': 'fixture://public/not-authorized.txt',
              'review': review, 'missing': report}[args.case]
    if args.case == 'missing':
        del resources[report]
    run_id = 'demo-offline-' + uuid4().hex
    output = root / 'evidence' / run_id
    output.mkdir(parents=True, mode=0o700)
    record = {
        'build': 'aisa-demo-launcher-0.1', 'run_id': run_id,
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'mode': 'OFFLINE_SCRIPTED', 'task': args.task, 'case': args.case,
        'task_semantics': 'Recorded only; named case supplies scripted proposal. No language-model interpretation.',
        'paid_calls': 0, 'summary_generation': 'NOT_IMPLEMENTED',
        'bindings': {str(p.relative_to(root)): digest(p) for p in [
            root / 'config/objective.json', root / 'config/policy.json', Path(__file__).resolve()
        ] if p.is_relative_to(root)},
        'launcher_sha256': digest(Path(__file__)),
        'fixture_content_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'limitations': ['reference performance hard-deferred', 'L7 comparative acceptance incomplete', 'no production acceptance claim'],
        'status': 'STARTED',
    }
    def save():
        (output / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
    save()
    store = AppendOnlyEvidenceStore(output / 'events.jsonl', assets / 'schemas/primary_agent_event_v0.2.schema.json', config.event_schema_sha256)
    shadow = ScriptedShadowAdapter({review: ShadowResult('CHALLENGE', 'COMPLETED', ('T2_EVD',), 1, 1)})
    wrapper = StrictFixtureWrapper(resources)
    controller = AgentController(config, store, shadow, CapabilityBroker(), wrapper)
    print('OFFLINE SCRIPTED: no hosted models; no API calls. Ctrl+C stops this run.')
    try:
        result = controller.process({'capability': 'read_file', 'target': target,
                                     'parameters': {'encoding': 'utf-8'}, 'operation': 'USE'},
                                    RunContext(run_id, 'trace-' + uuid4().hex, config.objective['objective_id'], action_origin='HARNESS'))
        store.verify_chain()
        events = store.read_all()
        shadow_completed = any(e['trusted_metadata'].get('tier2_termination_reason') == 'COMPLETED'
                               and e['trusted_metadata'].get('tier2_outcome') == 'CHALLENGE' for e in events)
        observed = result.wrapper_result.observed_result if result.wrapper_result else None
        expected = {'permitted': 'EXECUTED', 'blocked': 'BLOCKED', 'review': 'CHALLENGED', 'missing': 'FAILED'}[args.case]
        passed = result.final_status == expected and (args.case != 'review' or shadow_completed)
        passed = passed and (observed == text if args.case == 'permitted' else observed is None)
        if args.case == 'missing':
            passed = passed and any('ContractError' in e.get('untrusted_data', {}).get('error_detail', '') for e in events)
        record.update(status=result.final_status, check='PASS' if passed else 'FAIL', observed_content=observed,
                      shadow_script_completed=shadow_completed, event_chain_verified=True,
                      missing_fixture_rejected=args.case == 'missing' and passed)
        code = 0 if passed else 1
    except KeyboardInterrupt:
        record.update(status='STOPPED', check='INCOMPLETE')
        code = 130
    except Exception as exc:
        record.update(status='ERROR', check='INCOMPLETE', error_type=type(exc).__name__)
        code = 1
    finally:
        record['ended_utc'] = datetime.now(timezone.utc).isoformat()
        record['file_hashes'] = {p.name: digest(p) for p in output.iterdir() if p.is_file() and p.name != 'run.json'}
        save()
    print(json.dumps(record, indent=2))
    print('Evidence:', output)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
