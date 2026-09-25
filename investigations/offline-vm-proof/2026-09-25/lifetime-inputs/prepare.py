#!/usr/bin/python3
"""Build fixed local investigation artifacts; never starts a VM."""
import hashlib,json,pathlib,subprocess
P=pathlib.Path
base=P('/home/bump/.local/state/eqemu-vm-proof');out=base/'lifetime-inputs'
original=(base/'first-vm-trial.py').read_text()
assert hashlib.sha256(original.encode()).hexdigest()=='d1282bf26dc69e061d7ce65871d3464604b24a6be5fdc31714b5667b153c0b23'
guest=(base/'first-trial-inputs/guest_trial.py').read_text().replace('EQEMU_TRIAL_RESULT ','EQEMU_LIFETIME_READY ')
guest=guest.replace("    subprocess.run(['systemctl','poweroff'],timeout=15,check=False)","    # Keep the guest alive so host-driven interruption must reclaim it.\n    while True: time.sleep(1)")
(out/'guest_trial.py').write_text(guest)
config=json.loads((base/'first-trial-inputs/user-data').read_text().split('\n',1)[1])
for item in config['write_files']:
    if item['path']=='/opt/eqemu-proof/guest_trial.py':item['content']=guest
(out/'user-data').write_text('#cloud-config\n'+json.dumps(config,indent=2)+'\n')
(out/'meta-data').write_text('instance-id: eqemu-lifetime-proof-v1\nlocal-hostname: eqemu-lifetime\n')
if not (out/'seed.iso').exists():subprocess.run(['cloud-localds',str(out/'seed.iso'),str(out/'user-data'),str(out/'meta-data')],check=True)
seed=out/'seed.iso';seedhash=hashlib.sha256(seed.read_bytes()).hexdigest()
required="{'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}"
manifest={}
for case in ['timeout','cancel','death']:
    code=original
    def change(old,new):
        global code
        if old not in code:raise ValueError('Replacement not found: '+old)
        code=code.replace(old,new)
    change("ROOT=BASE/'first-trial'",f"ROOT=BASE/'lifetime-tests'/'{case}'")
    change('eqemu-vm-first-trial.service',f'eqemu-vm-lifetime-{case}.service')
    change('eqemuvmtrial',f'eqemuvmlifetime{case}')
    change('eqemu-first-trial',f'eqemu-lt-{case}')
    change('def setup():\n', 'def setup():\n'+"    if not re.fullmatch(r'[a-z0-9-]{1,20}',NAME):raise RuntimeError('Domain name must use at most 20 ASCII lowercase letters, digits or hyphens')\n")
    change("'first-trial-inputs/seed.iso',378880,'01472af8cf232fb668cf24c03d3c361e4cebf1f3ae67a24a07e490e9cf305c2a'",f"'lifetime-inputs/seed.iso',{seed.stat().st_size},'{seedhash}'")
    change('RuntimeMaxSec=1800','RuntimeMaxSec=300')
    change("'-p','MemoryMax=1G'","'-p','MemoryMax=960M'")
    change('first synthetic offline VM trial; not full isolation acceptance','deliberately interrupted synthetic VM; never a successful workload')
    change("virsh('resume',s['uuid']);report['resumed_at']=time.time()","virsh('resume',s['uuid']);report['resumed_at']=time.time();write_json(EVIDENCE/'report.json',report)")
    change('EQEMU_TRIAL_RESULT ','EQEMU_LIFETIME_READY ')
    needle="                            frames.append(json.loads(line[len(b'EQEMU_LIFETIME_READY '):]))"
    change(needle,needle+f"""
                            guest=frames[0]
                            required={required}
                            if not isinstance(guest,dict) or guest.get('schema')!=1 or guest.get('kind')!='offline-container-trial' or guest.get('ok') is not True or not isinstance(guest.get('checks'),dict) or set(guest['checks'])!=required or any(v is not True for v in guest['checks'].values()):
                                raise RuntimeError('Guest readiness checks failed')
                            report['guest_report_untrusted']=guest
                            report['ready_at']=time.time();report['serial_bytes']=total
                            write_json(EVIDENCE/'report.json',report)
""")
    start=code.index("        report['serial_bytes']=total\n        # Serial closure")
    end=code.index("    except Exception as exc:report['error']=str(exc)",start)
    code=code[:start]+"        raise RuntimeError('Guest serial closed before host interruption')\n"+code[end:]
    change("        # Save only capped logs", """        if P('/sys/fs/cgroup',SLICE).exists():raise RuntimeError('Worker cgroup remains')
        receipt['cgroup_absent']=True
        receipt['readonly_inputs_unchanged']=all((DATA/name).is_file() and digest(DATA/name)==FILES[name][2] for name in ['seed.iso','fixture.iso'])
        # Save only capped logs""")
    change("    write_json(EVIDENCE/'cleanup.json',receipt)","    receipt['finished_at']=time.time()\n    write_json(EVIDENCE/'cleanup.json',receipt)")
    # A fixed case controller has no retry/reconciliation API. Keep baseline recovery separate.
    a=code.index('\ndef retry():');b=code.index('\ndef prepare_disk(',a);code=code[:a]+code[b:]
    a=code.index('\ndef reconcile():');b=code.index('\ndef cleanup(',a);code=code[:a]+code[b:]
    change("parser.add_argument('--retry',action='store_true');parser.add_argument('--reconcile-and-retry',action='store_true');",'')
    change('args.check,args.retry,args.reconcile_and_retry,args.worker,args.cleanup','args.check,args.worker,args.cleanup')
    change("    if args.reconcile_and_retry:\n        reconcile();retry()\n    elif args.retry:retry()\n    else:setup()","    setup()")
    path=out/(case+'-worker.py');path.write_text(code)
    compile(code,str(path),'exec')
    manifest[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
(out/'worker-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'seed_bytes':seed.stat().st_size,'seed_sha256':seedhash,'workers':manifest},indent=2))
