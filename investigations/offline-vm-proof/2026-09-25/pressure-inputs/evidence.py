"""Small bounded serial parser shared by local replay tests and generated workers."""
import json
SERIAL_LIMIT=1024**2
READY=b'EQEMU_PRESSURE_READY '
RESULT=b'EQEMU_PRESSURE_RESULT '
REQUIRED={'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}
class EvidenceError(RuntimeError):pass

def strict_json(data):
    # Bound nesting before invoking the JSON decoder, including on builds with a larger recursion limit.
    depth=0;quoted=False;escaped=False
    for byte in data:
        if quoted:
            if escaped:escaped=False
            elif byte==92:escaped=True
            elif byte==34:quoted=False
        elif byte==34:quoted=True
        elif byte in [91,123]:
            depth+=1
            if depth>32:raise EvidenceError('JSON nesting limit exceeded')
        elif byte in [93,125]:depth-=1
    def pairs(items):
        obj={}
        for key,value in items:
            if key in obj:raise EvidenceError('Duplicate JSON key')
            obj[key]=value
        return obj
    def constant(_):raise EvidenceError('Non-finite JSON number')
    try:return json.loads(data,object_pairs_hook=pairs,parse_constant=constant)
    except EvidenceError:raise
    except (ValueError,UnicodeError,RecursionError):raise EvidenceError('Malformed result JSON')

class SerialReader:
    def __init__(self):self.tail=b'';self.total=0;self.ready=False;self.result=False
    def feed(self,data):
        if self.total+len(data)>SERIAL_LIMIT:raise EvidenceError('Serial output limit exceeded')
        self.total+=len(data);self.tail+=data
        while b'\n' in self.tail:
            line,self.tail=self.tail.split(b'\n',1)
            if len(line)>65536:raise EvidenceError('Oversized serial line')
            prefix=READY if line.startswith(READY) else RESULT if line.startswith(RESULT) else None
            if prefix is None:continue
            if len(line)>16384:raise EvidenceError('Oversized result frame')
            obj=strict_json(line[len(prefix):])
            if prefix==READY:
                if self.ready:raise EvidenceError('Duplicate readiness frame')
                if not isinstance(obj,dict) or type(obj.get('schema')) is not int or obj['schema']!=1 or obj.get('kind')!='offline-container-trial' or obj.get('ok') is not True or not isinstance(obj.get('checks'),dict) or set(obj['checks'])!=REQUIRED or any(v is not True for v in obj['checks'].values()):
                    raise EvidenceError('Invalid readiness schema')
                self.ready=True;yield ('ready',obj)
            else:
                if not self.ready:raise EvidenceError('Result before readiness')
                if self.result:raise EvidenceError('Duplicate result frame')
                if not isinstance(obj,dict) or type(obj.get('schema')) is not int or obj['schema']!=1 or obj.get('kind')!='pressure-resource-result' or obj.get('ok') is not True or obj.get('checks')!={'disk_full':True,'cpu_done':True} or any(type(v) is not bool for v in obj['checks'].values()):
                    raise EvidenceError('Invalid result schema')
                self.result=True;yield ('result',obj)
        if len(self.tail)>65536:raise EvidenceError('Unterminated oversized serial line')
