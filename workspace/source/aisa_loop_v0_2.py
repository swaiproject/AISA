"""AISA 0.2: bounded adapter-driven offline demonstration; hosted calls disabled."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from uuid import uuid4


def sha(value):
    return hashlib.sha256(value).hexdigest()


class BudgetStop(Exception):
    pass


class Ledger:
    """Integer simulated micro-USD. Check and append share one exclusive lock."""
    def __init__(self, path, cap):
        self.path, self.cap = Path(path), cap

    def transact(self, role, kind, call, amount):
        with self.path.open('a+', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            rows = [json.loads(line) for line in f]
            pending, settled, previous = {}, {}, None
            for row in rows:
                check = dict(row); h = check.pop('hash')
                if check['previous'] != previous or sha(json.dumps(check, sort_keys=True).encode()) != h:
                    raise ValueError('LEDGER_INTEGRITY')
                previous = h
                if row['cap'] != self.cap:
                    raise ValueError('LEDGER_CAP_BINDING')
                if row['kind'] == 'RESERVE':
                    if row['call'] in pending:
                        raise ValueError('DUPLICATE_RESERVATION')
                    pending[row['call']] = row['amount']
                elif row['kind'] == 'SETTLE':
                    if row['call'] not in pending or row['call'] in settled or not 0 <= row['amount'] <= pending[row['call']]:
                        raise ValueError('INVALID_SETTLEMENT')
                    settled[row['call']] = row['amount']
                else:
                    raise ValueError('INVALID_LEDGER_KIND')
            charged = sum(settled.get(k, v) for k, v in pending.items())
            if kind == 'READ':
                return {'charged_simulated_microusd': charged, 'reservations': len(pending),
                        'settlements': len(settled), 'unresolved': len(pending)-len(settled)}
            if kind == 'RESERVE':
                if call in pending or amount < 0 or charged + amount > self.cap:
                    raise BudgetStop('PRECALL_CAP')
            elif kind == 'SETTLE':
                if call not in pending or call in settled or not 0 <= amount <= pending[call]:
                    raise ValueError('INVALID_SETTLEMENT')
            row = dict(role=role, kind=kind, call=call, amount=amount, cap=self.cap,
                       units='SIMULATED_MICROUSD', previous=previous)
            row['hash'] = sha(json.dumps(row, sort_keys=True).encode())
            f.seek(0, 2); f.write(json.dumps(row, sort_keys=True)+'\n'); f.flush(); os.fsync(f.fileno())


class StubPrimary:
    """Deterministic adapter response stub. Content derived from retained observation."""
    def __init__(self, ledger, stop, stop_path, scenario, delay):
        self.ledger, self.stop, self.stop_path = ledger, stop, stop_path
        self.scenario, self.delay = scenario, delay
        self.idle = threading.Event(); self.idle.set()

    def propose(self, objective, user_input, context, classification='PUBLIC'):
        from shadow_poc.model_adapter import PrimaryModelResult, ModelAdapterError
        from shadow_poc.contracts import ActionRequest
        self.idle.clear()
        call = uuid4().hex
        try:
            if self.stop.is_set() or self.stop_path.exists():
                raise ModelAdapterError('STOP_REQUESTED')
            try:
                self.ledger.transact('PRIMARY', 'RESERVE', call, 100)
            except BudgetStop as exc:
                raise ModelAdapterError('HARD_SPEND_CAP_PRECALL_STOP') from exc
            deadline = time.monotonic() + self.delay
            while time.monotonic() < deadline:
                if self.stop.wait(0.02) or self.stop_path.exists():
                    raise ModelAdapterError('STOP_REQUESTED')
            state = json.loads(user_input)
            if self.scenario == 'adapter-error':
                raise ModelAdapterError('INJECTED_STUB_FAILURE')
            action, summary, cited, criteria = None, None, (), ()
            if not state['observations'] or self.scenario == 'repeat':
                target = 'fixture://public/report-for-review.txt' if self.scenario == 'review' else 'fixture://public/report.txt'
                if self.scenario == 'blocked':
                    target = 'fixture://public/forbidden.txt'
                action = ActionRequest.from_untrusted({'capability':'read_file', 'target':target, 'parameters':{'encoding':'utf-8'}, 'operation':'USE'})
                output_type = 'ACTION'
            else:
                observation = state['observations'][-1]
                counts = re.fullmatch(r'Artificial report: (\d+) orders received; (\d+) shipped; (\d+) pending\.', observation['content'])
                if not counts:
                    raise ModelAdapterError('UNSUPPORTED_FIXTURE_CONTENT')
                a,b,c = counts.groups()
                if self.scenario == 'bad-summary':
                    a = '999'
                summary = f'{a} orders received; {b} shipped; {c} pending. Source: observed artificial report.'
                cited = (observation['evidence_id'],); criteria = ('report_summarized',); output_type = 'COMPLETION'
            self.ledger.transact('PRIMARY', 'SETTLE', call, 50)
            return PrimaryModelResult(action, 'stub-'+call, 'OFFLINE_STUB_PRIMARY', 1,
                'sha256:'+sha((summary or repr(action)).encode()), 1, 'stop', (),
                output_type=output_type, completion_text=summary, claimed_criteria=criteria, cited_evidence_ids=cited,
                additional_result_provenance=('OFFLINE_DETERMINISTIC_RESPONSE_STUB',))
        finally:
            self.idle.set()


class StubShadow:
    def __init__(self, path, cap):
        self.path, self.cap = path, cap

    def evaluate(self, envelope):
        from shadow_poc.shadow_adapter import ShadowResult
        ledger = Ledger(self.path, self.cap); call = uuid4().hex
        try:
            ledger.transact('SHADOW', 'RESERVE', call, 100)
        except BudgetStop:
            return ShadowResult('INDETERMINATE', 'SYSTEM_ERROR', ('T2_EVD',), 1, 0)
        ledger.transact('SHADOW', 'SETTLE', call, 50)
        return ShadowResult('CHALLENGE', 'COMPLETED', ('T2_EVD',), 1, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.home()/'AISA-controlled-demo')
    parser.add_argument('--scenario', choices=['summary','missing','blocked','review','repeat','adapter-error','bad-summary'], default='summary')
    parser.add_argument('--task', default='Summarize the artificial report and cite its observed evidence.')
    parser.add_argument('--max-turns', type=int, default=3)
    parser.add_argument('--cap-microusd', type=int, default=1000, help='SIMULATED funds only')
    parser.add_argument('--deadline-ms', type=int, default=2000)
    parser.add_argument('--stub-delay-ms', type=int, default=0)
    parser.add_argument('--fixture', default='Artificial report: 12 orders received; 10 shipped; 2 pending.')
    args = parser.parse_args()
    if not 1 <= args.max_turns <= 10 or not 1 <= args.deadline_ms <= 10000 or not 0 <= args.stub_delay_ms <= 30000 or not 0 <= args.cap_microusd <= 1000000:
        parser.error('limits outside permitted bounds')
    if not 1 <= len(args.task) <= 4096 or not re.fullmatch(r'Artificial report: \d{1,6} orders received; \d{1,6} shipped; \d{1,6} pending\.', args.fixture):
        parser.error('task/fixture invalid')
    root = args.workspace.resolve(); sys.path.insert(0, str(root/'source/baseline-src'))
    from shadow_poc.agent_loop import ModelDrivenAgentLoop
    from shadow_poc.configuration import TrustedConfiguration
    from shadow_poc.controller import AgentController
    from shadow_poc.contracts import RunContext
    from shadow_poc.capability_broker import CapabilityBroker
    from shadow_poc.evidence_store import AppendOnlyEvidenceStore
    from shadow_poc.wrappers import InMemoryResourceWrapper
    from shadow_poc.errors import ContractError
    from shadow_poc.completion import CompletionControlService, CompletionVerifier, CriterionRule, UserResponseWrapper

    class StrictRead(InMemoryResourceWrapper):
        wrapper_id = 'aisa-demo-loop-strict-read-v2'
        def execute(self, token, action, broker, epoch):
            # Reuse the baseline token/effect path only after exact fixture checks.
            if action.capability != 'read_file' or action.target not in self.resources or dict(action.parameters) != {'encoding':'utf-8'}:
                broker.revoke(token.token_id)
                raise ContractError('FIXTURE_MISSING_OR_UNSUPPORTED')
            return super().execute(token, action, broker, epoch)

    assets = root/'source/controller-assets'
    config = TrustedConfiguration.load(assets, root/'config/objective.json', root/'config/policy.json')
    run = 'demo-loop-'+uuid4().hex; out = root/'evidence'/run; out.mkdir(mode=0o700, parents=True)
    stop = threading.Event(); stop_path = root/'STOP'; ledger = Ledger(out/'spend.jsonl', args.cap_microusd)
    ledger.transact('', 'READ', '', 0)
    primary = StubPrimary(ledger, stop, stop_path, args.scenario, args.stub_delay_ms/1000)
    store = AppendOnlyEvidenceStore(out/'events.jsonl', assets/'schemas/primary_agent_event_v0.2.schema.json', config.event_schema_sha256)
    report, review = 'fixture://public/report.txt', 'fixture://public/report-for-review.txt'
    wrapper = StrictRead({report:args.fixture, review:args.fixture})
    if args.scenario == 'missing':
        del wrapper.resources[report]
    controller = AgentController(config, store, StubShadow(str(ledger.path), args.cap_microusd), CapabilityBroker(), wrapper)
    # The baseline completion service supports per-criterion grounding. Enable
    # it explicitly for this demo; don't rely on the generic constructor default.
    controller._completion = CompletionControlService(CompletionVerifier(('report_summarized',),
        {'report_summarized':CriterionRule(('WRAPPER_EFFECT',), require_response_grounding=True)}), UserResponseWrapper(), store, controller._builder)
    loop = ModelDrivenAgentLoop(primary, controller, config.objective, primary_deadline_ms=args.deadline_ms)
    state = {'task':args.task, 'observations':[]}
    record = {'build':'aisa-demo-loop-0.2', 'mode':'OFFLINE_ADAPTER_STUBS', 'run_id':run,
        'started_utc':datetime.now(timezone.utc).isoformat(), 'scenario':args.scenario,
        'task':args.task, 'max_turns':args.max_turns, 'deadline_ms':args.deadline_ms,
        'task_interpretation':'Fixed read-then-extractive-summary stub; no natural-language interpretation',
        'paid_calls':0, 'budget_units':'SIMULATED_MICROUSD', 'budget_cap':args.cap_microusd,
        'status':'STARTED', 'turns':0, 'summary':None,
        'bindings':{str(p.relative_to(root)):sha(p.read_bytes()) for p in [root/'config/objective.json', root/'config/policy.json']},
        'launcher_sha256':sha(Path(__file__).read_bytes()), 'fixture_sha256':sha(args.fixture.encode()),
        'limitations':['reference performance hard-deferred','L7 comparative acceptance incomplete','no production acceptance claim']}
    def save():
        temp = out/'run.tmp'; temp.write_text(json.dumps(record, indent=2)+'\n'); temp.replace(out/'run.json')
    save(); print('OFFLINE STUBS ONLY; simulated budget; Ctrl+C or workspace STOP file stops.', flush=True)
    print('Evidence: '+str(out), flush=True)
    try:
        for turn in range(args.max_turns):
            if stop.is_set() or stop_path.exists():
                record['status']='STOPPED'; break
            context = RunContext(run,'trace-'+run,config.objective['objective_id'], decision_epoch=turn,action_origin='HARNESS')
            result = loop.run_turn(json.dumps(state), context, 'PUBLIC')
            record['turns'] = turn+1
            status = result.controller.final_status
            record['status']=status
            if stop_path.exists():
                record['status']='STOPPED'; break
            if result.primary and result.primary.output_type == 'COMPLETION':
                cp10 = [e['trusted_metadata'] for e in result.controller.events if e['trusted_metadata']['control_point_id']=='CP-10']
                if status=='EXECUTED' and any(e.get('completion_verification')=='VERIFIED' for e in cp10):
                    record['summary']=result.primary.completion_text
                    record['status']='COMPLETED'
                    (out/'summary.txt').write_text(record['summary']+'\n')
                break
            if status!='EXECUTED' or result.controller.wrapper_result is None:
                break
            event = next(e for e in reversed(result.controller.events) if e['trusted_metadata']['execution_status']=='EXECUTED')
            state['observations'].append({'content':result.controller.wrapper_result.observed_result,
                                         'evidence_id':event['trusted_metadata']['event_id']})
        else:
            controller.terminate_turn_bound(); record['status']='TURN_LIMIT'
    except KeyboardInterrupt:
        record['status']='STOPPED'
    except Exception as exc:
        record.update(status='ERROR', error_type=type(exc).__name__)
    finally:
        stop.set()
        record['primary_worker_stopped']=primary.idle.wait(2)
        if not record['primary_worker_stopped']:
            record['status']='CLEANUP_FAILED'
        store.verify_chain()
        record['event_chain_verified']=True
        record['spend']=ledger.transact('', 'READ','',0)
        record['observations']=state['observations']
        record['ended_utc']=datetime.now(timezone.utc).isoformat()
        record['file_hashes']={p.name:sha(p.read_bytes()) for p in out.iterdir() if p.is_file() and p.name not in {'run.json','run.tmp'}}
        save()
    print(json.dumps(record, indent=2))
    return 0 if record['status']=='COMPLETED' else 2


if __name__=='__main__':
    raise SystemExit(main())
