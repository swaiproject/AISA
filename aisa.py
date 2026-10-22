"""Offline-only publication launcher. No hosted execution option."""
import argparse,subprocess,sys
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('case',choices=['summary','review','permitted','blocked','missing'])
 a=p.parse_args(); root=Path(__file__).resolve().parent/'workspace'
 if a.case in ['summary','review']:
  command=['aisa_confirmation_v0_5.py','--mode','mock','--scenario',a.case]
 else:command=['aisa_demo_v0_1.py','--case',a.case]
 return subprocess.call([sys.executable,str(root/'source'/command[0]),'--workspace',str(root)]+command[1:])
if __name__=='__main__':raise SystemExit(main())
