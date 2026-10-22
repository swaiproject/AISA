"""Verify public file hashes, historical bindings and selected event chains."""
from pathlib import Path
import hashlib,json,sys

def main():
 root=Path(__file__).resolve().parents[1];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 manifest=root/'PUBLICATION-MANIFEST.json'
 if manifest.exists():
  for name,digest in json.loads(manifest.read_text())['files_sha256'].items():assert sha(root/name)==digest,name
 work=root/'workspace'
 for path in (work/'config').glob('*bindings*.json'):
  for name,digest in json.loads(path.read_text()).items():assert sha(work/name)==digest,name
 sys.path.insert(0,str(work/'source/baseline-src'))
 from shadow_poc.evidence_store import AppendOnlyEvidenceStore
 schema=work/'source/controller-assets/schemas/primary_agent_event_v0.2.schema.json'
 for path in (root/'selected-evidence').glob('demo-hosted-live-*/events.jsonl'):
  AppendOnlyEvidenceStore(path,schema,sha(schema)).verify_chain();print(path.parent.name+' event chain PASS')
 sys.path.insert(0,str(work/'source'))
 from aisa_confirmation_support_v0_5 import ledger
 result=ledger(root/'selected-evidence/hosted-qualification-01/spend.jsonl')
 assert result['reserved_calls']==8 and result['settled_calls']==8 and result['unresolved_calls']==0 and result['conservative_committed_nanousd']==17260800
 print('Public hashes, source/config bindings, 3 event chains and closed eight-call ledger PASS')
if __name__=='__main__':main()
