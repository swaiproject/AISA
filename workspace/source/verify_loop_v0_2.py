"""Integration checks for saved-script adapter loop. No network calls."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    p=argparse.ArgumentParser(); p.add_argument('--workspace',type=Path,default=Path.home()/'AISA-controlled-demo'); a=p.parse_args()
    root=a.workspace.resolve(); launcher=Path(__file__).with_name('aisa_loop.py')
    if not launcher.exists():
        launcher=root/'source/aisa_loop_v0_2.py'
    results=[]
    def start(extra):
        return subprocess.Popen([sys.executable,str(launcher),'--workspace',str(root)]+extra,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def finish(child):
        stdout,stderr=child.communicate(timeout=20)
        assert not stderr,stderr
        line=next(x for x in stdout.splitlines() if x.startswith('Evidence: '))
        folder=Path(line[len('Evidence: '):]); r=json.loads((folder/'run.json').read_text())
        assert r['primary_worker_stopped'] and r['event_chain_verified'],r
        return r,folder
    def check(name,args,test):
        r,folder=finish(start(args)); assert test(r,folder),r
        results.append({'case':name,'status':'PASS','run_id':r['run_id']}); print(name,'PASS',flush=True)
    if (root/'STOP').exists():
        raise SystemExit('STOP file already exists; remove only when intentionally resuming.')
    check('summary',[],lambda r,f:r['status']=='COMPLETED' and r['turns']==2 and '12 orders' in (f/'summary.txt').read_text() and r['spend']['reservations']==2)
    check('changed-content',['--fixture','Artificial report: 31 orders received; 24 shipped; 7 pending.'],lambda r,f:r['status']=='COMPLETED' and '31 orders' in r['summary'] and '24 shipped' in r['summary'])
    check('missing',['--scenario','missing'],lambda r,f:r['status']=='FAILED' and r['summary'] is None and not(f/'summary.txt').exists())
    check('blocked',['--scenario','blocked'],lambda r,f:r['status']=='BLOCKED' and not r['observations'])
    def reviewed(r,f):
        events=[json.loads(x)['trusted_metadata'] for x in (f/'events.jsonl').read_text().splitlines()]
        return r['status']=='CHALLENGED' and any(e.get('tier2_termination_reason')=='COMPLETED' and e.get('tier2_outcome')=='CHALLENGE' for e in events) and r['spend']['reservations']==2
    check('shadow-reservation',['--scenario','review'],reviewed)
    check('turn-limit',['--scenario','repeat','--max-turns','2'],lambda r,f:r['status']=='TURN_LIMIT' and r['turns']==2 and r['summary'] is None)
    check('zero-budget',['--cap-microusd','0'],lambda r,f:r['summary'] is None and r['spend']['reservations']==0)
    check('second-call-budget',['--cap-microusd','100'],lambda r,f:r['summary'] is None and r['spend']['reservations']==1)
    check('shadow-budget',['--scenario','review','--cap-microusd','100'],lambda r,f:r['summary'] is None and r['spend']['reservations']==1)
    check('adapter-error',['--scenario','adapter-error'],lambda r,f:r['summary'] is None and r['spend']['unresolved']==1)
    check('bad-summary',['--scenario','bad-summary'],lambda r,f:r['status']=='COMPLETION_REJECTED' and not(f/'summary.txt').exists())
    check('deadline',['--stub-delay-ms','3000','--deadline-ms','100'],lambda r,f:r['summary'] is None and r['spend']['unresolved']==1)
    stop=root/'STOP'
    try:
        with stop.open('x') as f:f.write('verification stop request\n')
        check('stop-before-call',[],lambda r,f:r['status']=='STOPPED' and r['spend']['reservations']==0)
    finally:
        stop.unlink()
    child=start(['--stub-delay-ms','5000','--deadline-ms','9000'])
    # Synchronize on this child's unique directory printed before the call.
    first=child.stdout.readline(); second=child.stdout.readline()
    assert second.startswith('Evidence: '), (first,second)
    folder=Path(second.strip()[len('Evidence: '):])
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if 'RESERVE' in (folder/'spend.jsonl').read_text():break
        time.sleep(.01)
    else:raise AssertionError('delayed call did not reserve')
    child.send_signal(signal.SIGINT)
    stdout,stderr=child.communicate(timeout=10); assert not stderr,stderr
    r=json.loads((folder/'run.json').read_text())
    assert r['status']=='STOPPED' and r['primary_worker_stopped'] and r['spend']['unresolved']==1,r
    results.append({'case':'interrupt-during-call','status':'PASS','run_id':r['run_id']}); print('interrupt-during-call PASS')
    report={'mode':'OFFLINE_STUBS','paid_calls':0,'checks':results,'status':'PASS'}
    path=root/'evidence'/('loop-checks-'+str(time.time_ns())+'.json')
    path.write_text(json.dumps(report,indent=2)+'\n'); print('Verification report:',path)


if __name__=='__main__':main()
