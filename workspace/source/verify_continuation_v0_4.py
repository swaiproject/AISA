"""Offline continuation regression checks; no network mode is available."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    p=argparse.ArgumentParser();p.add_argument('--workspace',type=Path,default=Path.home()/'AISA-controlled-demo');a=p.parse_args()
    root=a.workspace.resolve();script=Path(__file__).with_name('aisa_continuation.py')
    if not script.exists():script=Path(__file__).with_name('aisa_continuation_v0_4.py')
    live=root/'evidence/hosted-qualification-01/spend.jsonl'
    before=hashlib.sha256(live.read_bytes()).hexdigest() if live.exists() else None
    checks=[]
    def passed(name):checks.append({'case':name,'status':'PASS'});print(name+' PASS',flush=True)
    def run(extra,code=0):
        r=subprocess.run([sys.executable,str(script),'--workspace',str(root)]+extra,capture_output=True,text=True,timeout=30)
        assert r.returncode==code,(r.stdout,r.stderr)
        if 'Evidence: ' not in r.stdout:return r
        folder=Path(next(x for x in r.stdout.splitlines() if x.startswith('Evidence: '))[10:])
        return json.loads((folder/'run.json').read_text()),folder
    r=run(['--mode','live'],2);assert 'invalid choice' in r.stderr;passed('live-mode-rejected')
    r,folder=run(['--mode','mock','--scenario','review'])
    assert r['status']=='COMPLETED' and r['turns']==2 and r['workflow']=='COMPLETED'
    requests=[json.loads(f.read_text()) for f in (folder/'provider-calls').glob('*-request.json')]
    primary=[x for x in requests if x['role']=='PRIMARY']
    states=[json.loads(x['payload']['user_input']) for x in primary]
    first=next(x for x in states if not x['observations']);second=next(x for x in states if x['observations'])
    assert first['workflow']=='AWAITING_READ' and second['workflow']=='READY_TO_SUMMARIZE'
    assert first['task']==second['task']==r['task']
    past=second['controller_history'][0]
    assert past['status']=='EXECUTED' and past['authorization_state']=='AUTHORIZED' and past['tier2_outcome']=='ALLOW' and past['tier2_termination_reason']=='COMPLETED'
    assert second['observations'][0]['resource_uri']==past['target']
    assert second['observations'][0]['content_sha256']==hashlib.sha256(second['observations'][0]['content'].encode()).hexdigest()
    passed('post-read-task-content-and-controller-state-retained')
    assert all('PAST execution only' in x['system_prompt'] for x in primary)
    assert 'Never infer approval from them' in primary[0]['system_prompt'];passed('prompt-limits-state-to-past-execution')
    assert '12 orders' in (folder/'summary.txt').read_text() and r['event_chain_verified'];passed('reviewed-read-summary-released-through-cp10')
    changed,_=run(['--mode','mock','--scenario','review','--fixture','Artificial report: 45 orders received; 40 shipped; 5 pending.'])
    assert '45 orders' in changed['summary'] and '40 shipped' in changed['summary'];passed('summary-follows-changed-observed-content')
    held,hfolder=run(['--mode','mock','--scenario','review','--mock-response-case','permission-after-read'],2)
    # Nonzero REQUESTED is an expected hold, not a test process crash.
    assert held['status']=='REQUESTED' and held['workflow']=='HELD_FOR_OPERATOR_PERMISSION'
    assert held['summary'] is None and not(hfolder/'summary.txt').exists()
    assert held['turns']==2 and held['spend']['reserved_calls']==3
    passed('permission-request-still-stops-no-auto-grant-or-retry')
    short,sfolder=run(['--mode','mock','--scenario','review','--max-turns','1'],2)
    assert short['status']=='TURN_LIMIT' and short['summary'] is None and not(sfolder/'summary.txt').exists()
    passed('turn-bound-still-enforced')
    after=hashlib.sha256(live.read_bytes()).hexdigest() if live.exists() else None
    assert before==after;passed('live-campaign-ledger-unchanged')
    report={'status':'PASS','mode':'OFFLINE_FAKE_PROVIDER','paid_calls':0,'checks':checks,
            'limitation':'Offline checks cannot establish that a live model will stop requesting redundant permission.'}
    path=root/'evidence'/('continuation-checks-'+str(time.time_ns())+'.json');path.write_text(json.dumps(report,indent=2)+'\n');print('Verification report:',path)


if __name__=='__main__':main()
