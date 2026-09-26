# Extends the proven bounded build protocol. All guest semantic evidence remains untrusted.
RUNTIME_MANIFEST_SHA='b51d4751fe2a31689dd906b392da1e24d9510e26418067b09788f43b78403b28'
READY_FLAGS={'world','zone','instance','base_map','water_map','nav_map','quests','perl_plugins','world_time'}
MUTABLE_TABLES={'rule_values','logsys_categories','player_event_log_settings','eqtime','spawn_condition_values','respawn_times'}
CoreBuildProtocol=BuildProtocol

def hash_value(v):return isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) is not None

def validate_runtime_result(v,events):
    if not isinstance(v,dict) or set(v)!={'input_manifest_sha256','package_plan_sha256','negative','positive','disk_growth_bytes'}:raise RuntimeError('Runtime result shape')
    if v['input_manifest_sha256']!=RUNTIME_MANIFEST_SHA or not hash_value(v['package_plan_sha256']):raise RuntimeError('Runtime result identity')
    if type(v['disk_growth_bytes']) is not int or not 0<=v['disk_growth_bytes']<=8*GIB:raise RuntimeError('Runtime disk growth')
    keys={'accepted','missing_readiness','flags','samples','duration','exits','schema_sha256','state_before_sha256','state_after_sha256','changed_tables','shared','logs'}
    for name in ['negative','positive']:
        x=v[name];e=events[name];needed=READY_FLAGS-({'water_map'} if name=='negative' else set())
        if not isinstance(x,dict) or set(x)!=keys or e['state']!='completed':raise RuntimeError('Incomplete runtime result')
        if x['accepted'] is not (name=='positive') or x['missing_readiness']!=(['water_map'] if name=='negative' else []):raise RuntimeError('Wrong runtime outcome')
        if x['flags']!=sorted(needed) or type(x['samples']) is not int or x['samples']!=e['samples'] or x['samples']<(7 if name=='positive' else 4):raise RuntimeError('Incomplete runtime readiness/samples')
        if type(x['duration']) not in [int,float] or x['duration']!=e['elapsed'] or x['duration']<(60 if name=='positive' else 15):raise RuntimeError('Incomplete health window')
        if x['exits']!={'zone':0,'world':0,'database':0} or any(type(n) is not int for n in x['exits'].values()):raise RuntimeError('Missing graceful shutdown')
        if any(not hash_value(x[k]) for k in ['schema_sha256','state_before_sha256','state_after_sha256']):raise RuntimeError('Missing state hashes')
        if not isinstance(x['changed_tables'],list) or any(not isinstance(t,str) for t in x['changed_tables']) or set(x['changed_tables'])-MUTABLE_TABLES:raise RuntimeError('Unexpected changed tables')
        for key in ['shared','logs']:
            records=x[key]
            if not isinstance(records,dict) or not 1<=len(records)<=12:raise RuntimeError('Bad file evidence')
            for path,r in records.items():
                if not re.fullmatch('[a-zA-Z0-9_.-]{1,80}',path) or not isinstance(r,dict) or set(r)!={'bytes','sha256'} or type(r['bytes']) is not int or not 0<r['bytes']<=768*1024**2 or not hash_value(r['sha256']):raise RuntimeError('Bad file identity')
        if not {'items','spells'}<=set(x['shared']) or set(x['logs'])!={'world-console.log','zone-console.log','database-console.log'}:raise RuntimeError('Missing runtime files')

class BuildProtocol(CoreBuildProtocol):
    def __init__(self,nonce):
        super().__init__(nonce);self.runtime_events={};self.current_case=None
    def accept(self,v):
        kind=v.get('kind')
        if kind=='ready':
            if v.get('runtime_manifest_sha256')!=RUNTIME_MANIFEST_SHA:raise RuntimeError('Runtime media identity')
            c=dict(v);del c['runtime_manifest_sha256'];return super().accept(c)
        if kind=='runtime':
            self.frames+=1
            if self.frames>1500 or self.result is not None or not self.preflight or v.get('nonce')!=self.nonce:raise RuntimeError('Runtime frame order/identity')
            case=v.get('case');state=v.get('state');base={'kind','nonce','case','state'}
            if case not in ['negative','positive']:raise RuntimeError('Unknown runtime case')
            if state=='started':
                if set(v)!=base or case in self.runtime_events or (case=='positive' and self.runtime_events.get('negative',{}).get('state')!='completed') or (case=='negative' and self.runtime_events):raise RuntimeError('Runtime case order')
                self.runtime_events[case]={'state':'started','samples':0,'elapsed':-1};self.current_case=case
            else:
                if case!=self.current_case or case not in self.runtime_events:raise RuntimeError('Wrong active runtime case')
                e=self.runtime_events[case]
                if state=='ready':
                    needed=READY_FLAGS-({'water_map'} if case=='negative' else set())
                    if set(v)!=base|{'flags','zone_id','instance_id'} or e['state']!='started' or v['flags']!=sorted(needed) or type(v['zone_id']) is not int or v['zone_id']!=202 or type(v['instance_id']) is not int or v['instance_id']!=0:raise RuntimeError('Invalid/duplicate runtime readiness')
                    e.update(state='ready',host_ready_at=time.monotonic())
                elif state=='sample':
                    if set(v)!=base|{'sample','elapsed'} or e['state']!='ready' or type(v['sample']) is not int or v['sample']!=e['samples']+1 or type(v['elapsed']) not in [int,float] or not e['elapsed']<v['elapsed']<=1800 or v['sample']>30:raise RuntimeError('Invalid runtime health sample')
                    e.update(samples=v['sample'],elapsed=v['elapsed'])
                elif state=='completed':
                    if set(v)!=base|{'accepted','missing_readiness'} or e['state']!='ready' or e['samples']<(7 if case=='positive' else 4) or e['elapsed']<(60 if case=='positive' else 15) or time.monotonic()-e['host_ready_at']<(60 if case=='positive' else 15) or v['accepted'] is not (case=='positive') or v['missing_readiness']!=(['water_map'] if case=='negative' else []):raise RuntimeError('Incomplete runtime completion')
                    e['state']='completed'
                else:raise RuntimeError('Unknown runtime state')
            return kind
        if kind=='result' and v.get('ok') is True:
            if set(self.runtime_events)!={'negative','positive'} or 'runtime' not in v:raise RuntimeError('No complete runtime evidence')
            validate_runtime_result(v['runtime'],self.runtime_events)
            c=dict(v);del c['runtime'];c['checks']=dict(v['checks'])
            if c['checks'].pop('runtime',None) is not True:raise RuntimeError('Runtime check missing')
            result=super().accept(c);self.result=v;return result
        return super().accept(v)
