"""Synthetic installed-runner seam for real AFK subprocess checks; starts no VM."""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation'))
import candidate
from common import PROFILE
FACTS=dict(candidate='a'*40,tree='b'*40,input_id='c'*64,manifest_sha256='d'*64,iso_sha256='e'*64,iso_bytes=1)


def main(root,mode):
    candidate.BASE=root
    upload=root/'uploads'/str(os.getuid());upload.mkdir(parents=True)
    candidate.POLL_SECONDS=.02
    def prepare(source,directory):
        iso=directory/'fake.iso';iso.write_bytes(b'x');return iso,FACTS
    def request(value):
        with (root/'calls').open('a') as f:f.write(value['op']+'\n')
        if value['op']=='run':return dict(started=True,run_id=value['run_id'],candidate=FACTS,build_id='f'*64)
        terminal=mode!='timeout' or value['op']=='cancel'
        code=0 if mode=='pass' else 1 if mode=='candidate' else 2
        return dict(version=1,run_id=value['run_id'],profile=PROFILE,candidate=FACTS,
                    build_id='0'*64 if mode=='wrong' else 'f'*64,terminal=terminal,
                    cleanup_complete=terminal and mode!='cleanup',accepted=code==0,exit_code=code)
    candidate.prepare=prepare;candidate.request=request
    return candidate.execute(root)

if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1]),sys.argv[2]))
