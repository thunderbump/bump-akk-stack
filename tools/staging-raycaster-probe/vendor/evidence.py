"""Strict fixed-query comparator. Missing movement evidence never passes collision."""
import math
import struct
import re

IDENTITY = ('id', 'npc', 'from', 'size', 'origin', 'adjusted', 'eyes', 'to',
            'target_size', 'target_eyes')


def parse_queries(text):
    rows = {}
    for payload in re.findall(r'SERVER_COLLISION_QUERY ([^\r\n]+)', text):
        row = dict(re.findall(r'(\w+)=([^\s]+)', payload))
        key = row['id']
        if key in rows:
            raise ValueError('duplicate query identity')
        for field in (*IDENTITY, 'time', 'entity', 'ground', 'los'):
            if field not in row:
                raise ValueError('missing query field: ' + field)
        for field in ('from', 'size', 'origin', 'adjusted', 'eyes', 'to', 'target_size',
                      'target_eyes', 'ground', 'time'):
            if not all(math.isfinite(float(n)) for n in row[field].split(',')):
                raise ValueError('nonfinite query')
        if row['los'] not in ('0', '1') or float(row['ground']) == -99999:
            raise ValueError('invalid ground/LoS result')
        rows[key] = row
    if set(rows) != {'start', 'clear', 'blocked'}:
        raise ValueError('incomplete fixed queries')
    if rows['clear']['los'] != '1' or rows['blocked']['los'] != '0':
        raise ValueError('positive clear/wall control failed')
    return rows


def compare(reference, candidate):
    """Exact identity, hit/miss and numeric ground, matching prior exact A/B tests."""
    if set(reference) != {'start', 'clear', 'blocked'} or set(candidate) != set(reference):
        raise ValueError('query set changed')
    for key, before in reference.items():
        after = candidate[key]
        for field in (*IDENTITY, 'los'):
            if before[field] != after[field]:
                raise ValueError('query identity/decision changed: ' + key + '/' + field)
        a, b = float(before['ground']), float(after['ground'])
        if not math.isfinite(a) or not math.isfinite(b) or a != b:
            raise ValueError('ground changed: ' + key)
    return True


def verdict(receipt):
    return {'fixed_queries': bool(receipt.get('fixed_queries_complete')),
            'collision': bool(receipt.get('fixed_queries_complete') and receipt.get('route_callers_complete')),
            'shutdown': bool(receipt.get('exits')) and all(v == 0 for v in receipt['exits'].values())}


def parse_route(text, backend, fixture=None):
    import json
    from pathlib import Path
    fixture = fixture or json.loads(Path('/route.json').read_text())
    """Require actual native calls, finite adjusted endpoints, ground and stopped pose."""
    records = []
    for payload in re.findall(r'SERVER_COLLISION_NATIVE ([^\r\n]+)', text):
        row = dict(re.findall(r'(\w+)=([^\s]+)', payload))
        if row.get('backend') != backend:
            raise ValueError('wrong native backend')
        for key in ('from', 'to', 'result'):
            if not all(math.isfinite(float(n)) for n in row[key].split(',')):
                raise ValueError('nonfinite native observation')
        if int(row['remaining']) == 0:
            raise ValueError('native observation budget exhausted')
        records.append(row)
    queries = parse_queries(text)
    if {r['entity'] for r in records} != {queries['start']['entity']}:
        raise ValueError('wrong native entity')
    if any(r['kind']=='teleport' for r in records):
        raise ValueError('teleport dispatched')
    required = {('GetGroundZ','FindBestZ'), ('CheckLosFN','CheckLoS'),
                ('FindDestGroundZ','FindBestZ'), ('AdjustRoute','FindBestZ'),
                ('MoveToCommand','dispatch'), ('AdjustRoute','node'), ('UpdatePathGround','admission'), ('FixZ','pose')}
    if not required <= {(r['caller'],r['kind']) for r in records}:
        raise ValueError('required native caller absent')
    if any(float(r['result']) <= 0 for r in records if r['kind']=='admission'):
        raise ValueError('partial/stuck/empty route')
    floors = {}
    for payload in re.findall(r'SERVER_COLLISION_FLOOR ([^\r\n]+)', text):
        row = dict(re.findall(r'(\w+)=([^\s]+)', payload))
        if row['id'] in floors: raise ValueError('duplicate floor')
        floors[row['id']] = row
    if set(floors) != {'route_start','transition','destination'}:
        raise ValueError('route floor samples absent')
    for name,point in zip(('route_start','transition','destination'), fixture['points']):
        if list(map(float, floors[name]['xyz'].split(','))) != point:
            raise ValueError('wrong route input')
    heights = [float(r['ground']) for r in floors.values()]
    if not all(math.isfinite(z) and z != -99999 for z in heights) or max(heights)-min(heights)<0.1:
        raise ValueError('no valid height transition')
    fixed = [r for r in records if r['caller'] in ('GetGroundZ','CheckLosFN')][:9]
    if [r['kind'] for r in fixed] != ['FindBestZ','CheckLoS']*3+['FindBestZ']*3:
        raise ValueError('fixed native call order')
    for index,name in enumerate(('start','clear','blocked')):
        q=queries[name]
        ground,los=fixed[index*2:index*2+2]
        if ground['from'] != q['adjusted'] or float(ground['result']) != float(q['ground']) or los['from'] != q['eyes'] or los['to'] != q['target_eyes'] or los['result'] != q['los']:
            # Compare float values, independent of Perl's decimal formatting.
            same=lambda a,b: [struct.pack('f',float(x)) for x in a.split(',')] == [struct.pack('f',float(x)) for x in b.split(',')]
            if not (same(ground['from'],q['adjusted']) and same(ground['result'],q['ground']) and same(los['from'],q['eyes']) and same(los['to'],q['target_eyes']) and los['result']==q['los']):
                raise ValueError('native fixed query differs from request')
    same=lambda a,b: [struct.pack('f',float(x)) for x in a.split(',')] == [struct.pack('f',float(x)) for x in b.split(',')]
    for native,name,point in zip(fixed[6:],('route_start','transition','destination'),fixture['points']):
        f32=lambda n: struct.unpack('f',struct.pack('f',n))[0]
        start_z=f32(fixture['points'][0][2])
        origin=f32(start_z+f32(point[2]-start_z))
        adjusted=','.join(map(str,[point[0],point[1],f32(origin+1)]))
        if not same(native['from'],adjusted) or not same(native['result'],floors[name]['ground']):
            raise ValueError('actual floor query differs')
    poses = []
    for payload in re.findall(r'SERVER_COLLISION_POSE ([^\r\n]+)', text):
        row = dict(re.findall(r'(\w+)=([^\s]+)', payload))
        if row.get('moving') not in ('0','1') or int(row['tick']) != len(poses)+1:
            raise ValueError('invalid pose state/tick')
        values = [float(n) for n in row['xyz'].split(',')]+[float(row['ground'])]
        if not all(math.isfinite(n) for n in values) or values[3] == -99999:
            raise ValueError('invalid pose/ground')
        f32=lambda n: struct.unpack('f',struct.pack('f',n))[0]
        adjusted=','.join(map(str,[values[0],values[1],f32(f32(values[2])+1)]))
        if not any(r['caller']=='GetGroundZ' and same(r['from'],adjusted) and same(r['result'],row['ground']) for r in records):
            raise ValueError('pose ground lacks matching actual query')
        # Use the observed model-dependent native GetZOffset.
        offsets = [float(r['result']) for r in records if r['caller']=='FixZ' and r['kind']=='pose']
        if row['moving']=='0' and abs(values[2]-values[3]-offsets[-1]) > fixture['pose_ground_tolerance']:
            raise ValueError('stopped pose not ground relative')
        poses.append(row)
    if len(poses)<3 or 'SERVER_COLLISION_ROUTE_DONE' not in text:
        raise ValueError('missing stopped route')
    for row in poses[-3:]:
        x,y,z=map(float,row['xyz'].split(','))
        if abs(x-fixture['points'][-1][0])>=0.5 or abs(y-fixture['points'][-1][1])>=0.5 or row['moving']!='0':
            raise ValueError('wrong final pose/state')
    def distance_to_segment(point, a, b):
        dx,dy=b[0]-a[0],b[1]-a[1]
        t=max(0,min(1,((point[0]-a[0])*dx+(point[1]-a[1])*dy)/(dx*dx+dy*dy)))
        return math.hypot(point[0]-a[0]-t*dx,point[1]-a[1]-t*dy)
    positions=[list(map(float,r['xyz'].split(','))) for r in poses]
    if not any(math.dist(p[:2],fixture['points'][0][:2])>5 and math.dist(p[:2],fixture['points'][-1][:2])>5 for p in positions[:-3]):
        raise ValueError('intermediate route progress absent')
    nodes=[list(map(float,r['to'].split(','))) for r in records if r['caller']=='AdjustRoute' and r['kind']=='node']
    for point,row in zip(positions,poses):
        if min(distance_to_segment(point,a,b) for a,b in zip(fixture['points'],fixture['points'][1:]))>2:
            raise ValueError('pose outside frozen route corridor')
        expected=[]
        for a,b in zip(nodes,nodes[1:]):
            dx,dy=b[0]-a[0],b[1]-a[1]
            if dx*dx+dy*dy==0: continue
            t=max(0,min(1,((point[0]-a[0])*dx+(point[1]-a[1])*dy)/(dx*dx+dy*dy)))
            if distance_to_segment(point,a,b)<=0.05:
                expected.append(a[2]+t*(b[2]-a[2]))
        if not expected or min(abs(point[2]-z) for z in expected)>0.05:
            if abs(point[2]-float(row['ground'])-offsets[-1])>0.05:
                raise ValueError('pose outside native interpolation and FixZ')
    return {'fixed_native':fixed, 'native':records,'floors':floors,'poses':poses}


def compare_route(before, after):
    """Exact fixed callers and nodes. Movement cadence is intentionally unconstrained."""
    if [{k:v for k,v in r.items() if k not in ('backend','entity','remaining')} for r in before['fixed_native']] != [{k:v for k,v in r.items() if k not in ('backend','entity','remaining')} for r in after['fixed_native']]:
        raise ValueError('actual fixed queries changed')
    if before['floors'] != after['floors']:
        raise ValueError('fixed route ground changed')
    def stable(route):
        return [{k:v for k,v in r.items() if k not in ('backend','entity','remaining')}
                for r in route['native'] if r['caller'] in ('AdjustRoute','UpdatePathGround')]
    if stable(before) != stable(after):
        raise ValueError('route admission/nodes changed')
    if before['poses'][-1]['xyz'] != after['poses'][-1]['xyz']:
        raise ValueError('final pose changed')
    return True
