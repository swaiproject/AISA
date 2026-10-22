"""AISA hosted integration 0.3: preflight by default; no automatic live calls."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.home()/'AISA-controlled-demo')
    parser.add_argument('--scenario', choices=['summary','review'], default='summary')
    parser.add_argument('--mode', choices=['preflight','mock'], default='preflight')
    parser.add_argument('--mock-response-case', choices=['normal','permission-after-read'],default='normal')
    parser.add_argument('--task', default='Summarize the artificial report and cite its observed evidence.')
    parser.add_argument('--max-turns', type=int, default=3)
    parser.add_argument('--deadline-ms', type=int, default=19000)
    parser.add_argument('--fixture', default='Artificial report: 12 orders received; 10 shipped; 2 pending.')
    args = parser.parse_args()
    if not 1 <= args.max_turns <= 3 or not 1 <= args.deadline_ms <= 19000:
        parser.error('limits outside permitted bounds')
    if not 1 <= len(args.task) <= 4096 or not re.fullmatch(r'Artificial report: \d{1,6} orders received; \d{1,6} shipped; \d{1,6} pending\.', args.fixture):
        parser.error('task/fixture invalid')
    root = args.workspace.resolve()
    binding_path=root/'config/continuation-bindings-v0_4.json'
    if not binding_path.is_file():
        parser.error('hosted installation bindings missing; run installer')
    bindings=json.loads(binding_path.read_text())
    if not bindings or any(not (root/name).is_file() or sha((root/name).read_bytes())!=value for name,value in bindings.items()):
        parser.error('hosted source/configuration binding mismatch')
    sys.path.insert(0, str(root/'source/baseline-src'))
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
    config = TrustedConfiguration.load(assets, root/'config/objective.json', root/'config/policy-hosted-v0_3.json')
    from aisa_continuation_support_v0_4 import HostedPrimary, HostedShadow, ledger as hosted_ledger, MODELS
    if args.mode=='preflight':
        print(json.dumps({'status':'LOCAL_PREFLIGHT_ONLY','models':MODELS,
            'key_present':bool(os.environ.get('OPENAI_API_KEY')),
            'account_access':'NOT_CHECKED','network_calls':0,
            'aggregate_proposed_cap_usd':1,'provider_attempt_limit':6,
            'qualification_required':True},indent=2))
        return 0
    run='demo-hosted-'+args.mode+'-'+uuid4().hex
    out=root/'evidence'/run;out.mkdir(mode=0o700,parents=True)
    stop=threading.Event();stop_path=root/'STOP'
    spend_path=out/'mock-spend.jsonl'
    call_dir=out/'provider-calls'
    primary=HostedPrimary(str(spend_path),args.mode,str(stop_path),str(call_dir))
    primary.cancel=stop
    store=AppendOnlyEvidenceStore(out/'events.jsonl',assets/'schemas/primary_agent_event_v0.2.schema.json',config.event_schema_sha256)
    report, review = 'fixture://public/report.txt', 'fixture://public/report-for-review.txt'
    wrapper = StrictRead({report:args.fixture, review:args.fixture})
    if args.scenario == 'missing':
        del wrapper.resources[report]
    controller = AgentController(config, store, HostedShadow(str(spend_path),args.mode,str(stop_path),str(call_dir),config.reason_codes), CapabilityBroker(), wrapper)
    # The baseline completion service supports per-criterion grounding. Enable
    # it explicitly for this demo; don't rely on the generic constructor default.
    controller._completion = CompletionControlService(CompletionVerifier(('report_summarized',),
        {'report_summarized':CriterionRule(('WRAPPER_EFFECT',), require_response_grounding=True)}), UserResponseWrapper(), store, controller._builder)
    loop = ModelDrivenAgentLoop(primary, controller, config.objective, primary_deadline_ms=args.deadline_ms)
    state = {'task':('Read the PUBLIC review fixture, then summarize its returned content. The Controller handles action authorization.' if args.scenario=='review' else args.task), 'observations':[], 'controller_history':[], 'workflow':'AWAITING_READ', 'mock_response_case':args.mock_response_case}
    record = {'build':'aisa-continuation-offline-0.4', 'mode':args.mode, 'run_id':run,
        'started_utc':datetime.now(timezone.utc).isoformat(), 'scenario':args.scenario,
        'task':state['task'], 'max_turns':args.max_turns, 'deadline_ms':args.deadline_ms,
        'task_interpretation':'Offline continuation candidate; fake provider responses only',
        'network_enabled':args.mode=='live', 'budget_units':'NANOUSD_CONSERVATIVE', 'aggregate_budget_usd':1,
        'models':MODELS, 'persistent_spend_path':str(spend_path),
        'paid_calls':0,
        'status':'STARTED', 'turns':0, 'summary':None,
        'bindings':{str(p.relative_to(root)):sha(p.read_bytes()) for p in [root/'config/objective.json', root/'config/policy-hosted-v0_3.json']},
        'installation_bindings_sha256':sha(binding_path.read_bytes()), 'support_module_sha256':sha(Path(__file__).with_name('aisa_continuation_support_v0_4.py').read_bytes()), 'launcher_sha256':sha(Path(__file__).read_bytes()), 'fixture_sha256':sha(args.fixture.encode()),
        'limitations':['reference performance hard-deferred','L7 comparative acceptance incomplete','no production acceptance claim']}
    def save():
        temp = out/'run.tmp'; temp.write_text(json.dumps(record, indent=2)+'\n'); temp.replace(out/'run.json')
    save(); print('Mode: '+args.mode+'; Ctrl+C or workspace STOP file stops local work.',flush=True)
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
            state['controller_history'].append({'turn':turn+1,'status':status,
                'output_type':result.primary.output_type if result.primary else None})
            if result.primary and result.primary.output_type == 'COMPLETION':
                cp10 = [e['trusted_metadata'] for e in result.controller.events if e['trusted_metadata']['control_point_id']=='CP-10']
                if status=='EXECUTED' and any(e.get('completion_verification')=='VERIFIED' for e in cp10):
                    record['summary']=result.primary.completion_text
                    record['status']='COMPLETED'
                    state['workflow']='COMPLETED'
                    (out/'summary.txt').write_text(record['summary']+'\n')
                break
            if status!='EXECUTED' or result.controller.wrapper_result is None:
                if result.primary and result.primary.output_type=='PERMISSION_REQUEST':
                    state['workflow']='HELD_FOR_OPERATOR_PERMISSION'
                break
            event = next(e for e in reversed(result.controller.events) if e['trusted_metadata']['execution_status']=='EXECUTED')
            action=result.primary.action
            state['observations'].append({'content':result.controller.wrapper_result.observed_result,
                'evidence_id':event['trusted_metadata']['event_id'], 'resource_uri':action.target,
                'status':'EXECUTED','content_sha256':sha((result.controller.wrapper_result.observed_result or '').encode())})
            state['controller_history'][-1].update(capability=action.capability,target=action.target,
                authorization_state=event['trusted_metadata']['authorization_state'],
                tier2_outcome=event['trusted_metadata']['tier2_outcome'],
                tier2_termination_reason=event['trusted_metadata']['tier2_termination_reason'])
            if action.capability=='read_file':
                state['workflow']='READY_TO_SUMMARIZE'
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
        
        import multiprocessing
        cleanup=[]
        for child in multiprocessing.active_children():
            child.terminate();child.join(1)
            if child.is_alive():child.kill();child.join(1)
            cleanup.append({'pid':child.pid,'stopped':not child.is_alive()})
        record['child_cleanup']=cleanup
        if any(not item['stopped'] for item in cleanup):record['status']='CLEANUP_FAILED'
        record['spend']=hosted_ledger(spend_path)
        record['observations']=state['observations']
        record['controller_history']=state['controller_history']
        record['workflow']=state['workflow']
        record['ended_utc']=datetime.now(timezone.utc).isoformat()
        record['file_hashes']={str(p.relative_to(out)):sha(p.read_bytes()) for p in out.rglob('*') if p.is_file() and p.name not in {'run.json','run.tmp'}}
        record['aggregate_ledger_sha256_at_close']=sha(spend_path.read_bytes())
        save()
    print(json.dumps(record, indent=2))
    return 0 if record['status']=='COMPLETED' else 2


if __name__=='__main__':
    raise SystemExit(main())
