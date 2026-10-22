"""Offline integration and spending-control checks; never enable live mode."""
from pathlib import Path
import argparse
import json
import multiprocessing
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from aisa_hosted_support_v0_3 import ledger,GuardedTransport,endpoint


def reserve_worker(path,queue):
    from uuid import uuid4
    try:ledger(path,'RESERVE','PRIMARY',uuid4().hex,1);queue.put(True)
    except ValueError:queue.put(False)


def main():
    p=argparse.ArgumentParser();p.add_argument('--workspace',type=Path,default=Path.home()/'AISA-controlled-demo');a=p.parse_args()
    root=a.workspace.resolve();sys.path.insert(0,str(root/'source/baseline-src'))
    launcher=Path(__file__).with_name('aisa_hosted.py')
    if not launcher.exists():launcher=Path(__file__).with_name('aisa_hosted_v0_3.py')
    results=[]
    def passed(name):results.append({'case':name,'status':'PASS'});print(name+' PASS',flush=True)
    def run(extra,expected=0):
        r=subprocess.run([sys.executable,str(launcher),'--workspace',str(root)]+extra,capture_output=True,text=True,timeout=30)
        assert r.returncode==expected,(r.stdout,r.stderr)
        return r
    r=run([]);assert 'LOCAL_PREFLIGHT_ONLY' in r.stdout;passed('preflight-no-network')
    r=run(['--mode','live'],2);assert 'live requires' in r.stderr;passed('live-approval-gate')
    r=run(['--mode','mock','--deadline-ms','1'],2)
    folder=Path(next(x for x in r.stdout.splitlines() if x.startswith('Evidence: '))[10:])
    stopped=json.loads((folder/'run.json').read_text())
    assert stopped['primary_worker_stopped'] and stopped['summary'] is None
    passed('primary-process-deadline-cleanup')
    for case in ['summary','review']:
        r=run(['--mode','mock','--scenario',case]);folder=Path(next(x for x in r.stdout.splitlines() if x.startswith('Evidence: '))[10:])
        doc=json.loads((folder/'run.json').read_text());assert doc['status']=='COMPLETED' and doc['event_chain_verified'] and doc['primary_worker_stopped']
        requests=[json.loads(x.read_text()) for x in (folder/'provider-calls').glob('*-request.json')]
        if case=='review':assert any(x['role']=='SHADOW' for x in requests)
        assert all(x['mode']=='mock' and x['max_output_tokens']<=512 for x in requests)
        passed('mock-'+case+'-actual-adapter-contracts')
    with tempfile.TemporaryDirectory(prefix='aisa-hosted-check-') as tmp:
        tmp=Path(tmp);path=tmp/'ledger.jsonl'
        ledger(path,'RESERVE','PRIMARY','first',100);ledger(path,'SETTLE','PRIMARY','first',50)
        assert ledger(path)['conservative_committed_nanousd']==50;passed('persistent-settlement')
        ledger(path,'RESERVE','SHADOW','uncertain',100)
        assert ledger(path)['unresolved_calls']==1 and ledger(path)['conservative_committed_nanousd']==150;passed('uncertain-charge-retained')
        try:ledger(path,'SETTLE','SHADOW','uncertain',101)
        except ValueError:pass
        else:raise AssertionError('overrun accepted')
        assert ledger(path)['unresolved_calls']==1;passed('overrun-not-refunded')
        capped=tmp/'cap.jsonl';ledger(capped,'RESERVE','PRIMARY','full',1_000_000_000)
        try:ledger(capped,'RESERVE','SHADOW','extra',1)
        except ValueError:pass
        else:raise AssertionError('cap bypassed')
        passed('aggregate-cap')
        concurrent=str(tmp/'concurrent.jsonl');ctx=multiprocessing.get_context('spawn');q=ctx.Queue()
        workers=[ctx.Process(target=reserve_worker,args=(concurrent,q)) for _ in range(10)]
        for worker in workers:worker.start()
        outcomes=[q.get(timeout=10) for _ in workers]
        for worker in workers:worker.join(10);assert worker.exitcode==0
        assert sum(outcomes)==6 and ledger(concurrent)['reserved_calls']==6;passed('atomic-six-call-limit')
        broken=tmp/'broken.jsonl';broken.write_text(path.read_text().replace('NANOUSD','TAMPERED',1))
        try:ledger(broken)
        except ValueError:pass
        else:raise AssertionError('tamper accepted')
        passed('ledger-tamper-rejected')
        altered=tmp/'altered';(altered/'config').mkdir(parents=True)
        (altered/'config/hosted-bindings-v0_3.json').write_text('{"missing.py":"0"}')
        r=run(['--workspace',str(altered)],2);assert 'binding mismatch' in r.stderr
        passed('configuration-binding-gate')
        from shadow_poc.model_adapter import OpenAICompatibleTransport,ProviderCompletion
        transport=GuardedTransport(endpoint('PRIMARY'),'PRIMARY',str(tmp/'transport.jsonl'),'live',str(tmp/'STOP'),str(tmp/'calls'))
        with patch.object(OpenAICompatibleTransport,'complete',side_effect=OSError('injected')) as call:
            try:transport.complete('JSON',{},10)
            except OSError:pass
            else:raise AssertionError('failure hidden')
            assert call.call_count==1
        assert ledger(transport.path)['unresolved_calls']==1;passed('provider-failure-keeps-reservation')
        (tmp/'STOP').write_text('stop')
        with patch.object(OpenAICompatibleTransport,'complete',side_effect=AssertionError('network forbidden')):
            try:transport.complete('JSON',{},10)
            except Exception as exc:assert str(exc)=='STOP_REQUESTED'
        assert ledger(transport.path)['reserved_calls']==1;passed('stop-before-provider')
        (tmp/'STOP').unlink()
        excessive=ProviderCompletion('{}',999999,'fake-overrun',transport.endpoint.model,1,'stop',())
        with patch.object(OpenAICompatibleTransport,'complete',return_value=excessive):
            try:transport.complete('JSON',{},10)
            except Exception as exc:assert str(exc)=='PROVIDER_TOKENS_EXCEED_RESERVATION'
            else:raise AssertionError('overrun accepted')
        assert ledger(transport.path)['halted']
        try:ledger(transport.path,'RESERVE','PRIMARY','after-halt',1)
        except ValueError:pass
        else:raise AssertionError('halt bypassed')
        passed('provider-overrun-halts-campaign')
    report={'status':'PASS','network_calls':0,'checks':results,'note':'Fake provider responses; account access and live suitability NOT established.'}
    output=root/'evidence'/('hosted-offline-checks-'+str(time.time_ns())+'.json');output.write_text(json.dumps(report,indent=2)+'\n')
    print('Verification report:',output)


if __name__=='__main__':main()
