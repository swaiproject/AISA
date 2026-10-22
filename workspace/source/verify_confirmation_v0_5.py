"""Offline confirmation checks; never spend or extend the live ledger."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from aisa_confirmation_support_v0_5 import ledger


def main():
    p=argparse.ArgumentParser();p.add_argument('--workspace',type=Path,default=Path.home()/'AISA-controlled-demo');a=p.parse_args();root=a.workspace.resolve()
    script=Path(__file__).with_name('aisa_confirmation.py')
    if not script.exists():script=Path(__file__).with_name('aisa_confirmation_v0_5.py')
    live=root/'evidence/hosted-qualification-01/spend.jsonl';before=hashlib.sha256(live.read_bytes()).hexdigest() if live.exists() else None
    checks=[]
    def passed(name):checks.append({'case':name,'status':'PASS'});print(name+' PASS',flush=True)
    def run(extra,code=0):
        r=subprocess.run([sys.executable,str(script),'--workspace',str(root)]+extra,capture_output=True,text=True,timeout=30)
        assert r.returncode==code,(r.stdout,r.stderr)
        return r
    r=run(['--mode','live','--scenario','review'],2);assert 'requires' in r.stderr;passed('explicit-extension-approval-required')
    r=run(['--mode','mock','--scenario','review']);folder=Path(next(x for x in r.stdout.splitlines() if x.startswith('Evidence: '))[10:]);record=json.loads((folder/'run.json').read_text())
    assert record['status']=='COMPLETED' and record['turns']==2 and record['spend']['reserved_calls']==3 and record['controller_history'][0]['tier2_outcome']=='ALLOW';passed('review-to-summary-with-three-mock-calls')
    r=run(['--mode','mock','--scenario','review','--mock-response-case','permission-after-read'],2);folder=Path(next(x for x in r.stdout.splitlines() if x.startswith('Evidence: '))[10:]);record=json.loads((folder/'run.json').read_text())
    assert record['status']=='REQUESTED' and record['summary'] is None;passed('permission-hold-retained')
    with tempfile.TemporaryDirectory(prefix='aisa-extension-test-') as tmp:
        path=Path(tmp)/'ledger.jsonl'
        for i in range(5):
            ledger(path,'RESERVE','PRIMARY',str(i),100)
            ledger(path,'SETTLE','PRIMARY',str(i),50)
        old=path.read_bytes();assert ledger(path)['attempt_limit']==6
        ledger(path,'EXTEND',telemetry={'approved_attempt_limit':8,'additional_attempts':3,'basis':'five attempts already used'})
        assert path.read_bytes().startswith(old) and ledger(path)['conservative_committed_nanousd']==250 and ledger(path)['attempt_limit']==8;passed('extension-appends-preserves-prior-cost-and-five-attempts')
        for i in range(5,8):ledger(path,'RESERVE','SHADOW',str(i),100)
        try:ledger(path,'RESERVE','PRIMARY','ninth',1)
        except ValueError:pass
        else:raise AssertionError('ninth attempt accepted')
        assert ledger(path)['aggregate_cap_usd']==1;passed('three-additional-attempts-only-dollar-cap-unchanged')
        sys.path.insert(0,str(root/'source'))
        from aisa_hosted_support_v0_3 import ledger as old_ledger
        try:old_ledger(path)
        except ValueError:pass
        else:raise AssertionError('old executor accepted extended ledger')
        passed('old-live-executor-rejects-extended-campaign')
    after=hashlib.sha256(live.read_bytes()).hexdigest() if live.exists() else None
    assert before==after;passed('actual-live-ledger-unchanged-offline')
    report={'status':'PASS','network_calls':0,'checks':checks}
    output=root/'evidence'/('confirmation-offline-checks-'+str(time.time_ns())+'.json');output.write_text(json.dumps(report,indent=2)+'\n');print('Verification report:',output)


if __name__=='__main__':main()
