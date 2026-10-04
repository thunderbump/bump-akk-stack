#!/usr/bin/python3 -I
"""Revoke this helper only; preserve evidence, uploads and the diagnostic runner."""
import fcntl
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import BASE, HERE
import host
from install import POLICY, RULE


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1:raise ValueError('Use sudo disable.py without arguments')
    host.S.verify_installation()
    with (BASE/'request.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        record=host.S.read_json(BASE/'installation.json');record['enabled']=False
        host.S.write_json(BASE/'installation.json',record)
        if POLICY.exists():
            host.S.safe_path(POLICY)
            if POLICY.read_text()!=RULE:raise ValueError('Changed sudo policy; preserve for inspection')
            POLICY.unlink();host.S.command(['/usr/sbin/visudo','-c'])
        for root in (BASE/'runs').iterdir():
            owner=host.S.read_json(root/'owner.json')
            if 'recipe' in owner:
                suite=host.suite_for(root,owner)
                if not suite.quiescent(suite.properties(suite.UNIT)):
                    suite.run(['/usr/bin/systemctl','stop',suite.UNIT],timeout=330)
                result=host.report(root.name,owner['uid'])
                if not result['cleanup_complete']:raise ValueError('Admission revoked; cleanup needs inspection: '+root.name)
    print('Build helper disabled; evidence retained; diagnostic runner unchanged.')

if __name__=='__main__':main()
