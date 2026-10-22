"""Run retained offline checks in an isolated workspace, without credentials."""
from pathlib import Path
import json,os,shutil,subprocess,sys,tempfile,time

def main():
 repo=Path(__file__).resolve().parents[1];results=[]
 env=dict(os.environ);env.pop('OPENAI_API_KEY',None);env['PYTHONDONTWRITEBYTECODE']='1'
 with tempfile.TemporaryDirectory(prefix='aisa-publication-') as tmp:
  work=Path(tmp)/'workspace';shutil.copytree(repo/'workspace',work)
  for version in ['loop_v0_2','hosted_v0_3','continuation_v0_4','confirmation_v0_5']:
   r=subprocess.run([sys.executable,str(work/'source'/('verify_'+version+'.py')),'--workspace',str(work)],capture_output=True,text=True,env=env,timeout=180)
   print(r.stdout,end='');assert r.returncode==0,r.stderr+r.stdout
   results.append({'suite':version,'checks_passed':r.stdout.count(' PASS'),'status':'PASS'})
  expected={'permitted':'EXECUTED','blocked':'BLOCKED','review':'CHALLENGED','missing':'FAILED'}
  for case,status in expected.items():
   r=subprocess.run([sys.executable,str(work/'source/aisa_demo_v0_1.py'),'--workspace',str(work),'--case',case],capture_output=True,text=True,env=env,timeout=30)
   assert r.returncode==0,r.stderr+r.stdout
   folder=Path(next(x[10:] for x in r.stdout.splitlines() if x.startswith('Evidence: ')))
   doc=json.loads((folder/'run.json').read_text());assert doc['status']==status and doc['check']=='PASS'
   if case=='missing':assert doc['missing_fixture_rejected']
   results.append({'strict_fixture':case,'status':'PASS'});print(case+' PASS')
 out=repo/'validation-output';out.mkdir(exist_ok=True)
 report={'status':'PASS','python':sys.version,'platform':sys.platform,'mode':'OFFLINE_ONLY','credential_removed_from_children':True,'checks':results,'limits':'No exact historical locked-environment rebuild; no hosted calls or production qualification.'}
 (out/'offline-reproduction.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
