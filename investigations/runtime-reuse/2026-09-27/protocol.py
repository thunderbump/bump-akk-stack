# Generic bounded scenario evidence; game checks remain in the guest adapter.
ReuseProtocol=BuildProtocol


class BuildProtocol(ReuseProtocol):
    def __init__(self,nonce):
        super().__init__(nonce);self.reuse_verified=False;self.diagnostic_bytes=0;self.streams={};self.event_count=0

    def accept(self,value):
        kind=value.get('kind')
        if kind not in ['reuse','scenario-event','diagnostic','result']:return super().accept(value)
        if self.result is not None or not self.ready or value.get('nonce')!=self.nonce:raise RuntimeError('Scenario frame identity/order')
        self.frames+=1
        if self.frames>1500:raise RuntimeError('Scenario frame count')
        if kind=='reuse':
            if self.reuse_verified:raise RuntimeError('Duplicate build consumption')
            result=dict(value,kind='result');super().accept(result)
            self.result=None;self.reuse_verified=True;return kind
        if kind=='scenario-event':
            self.event_count+=1
            if self.event_count>100 or not re.fullmatch('[a-z0-9-]{1,60}',value.get('name','')) or not isinstance(value.get('value'),dict):raise RuntimeError('Scenario event bounds')
            return kind
        if kind=='diagnostic':
            size=len(json.dumps(value).encode())
            name=value.get('stream');index=value.get('index');count=value.get('chunks');text=value.get('text');meta=value.get('meta')
            if (not isinstance(name,str) or not re.fullmatch('[a-z0-9-]{1,60}',name) or type(index) is not int
                    or type(count) is not int or not 1<=count<=40 or not isinstance(text,str) or len(text)>1024
                    or not isinstance(meta,dict) or type(meta.get('input_bytes')) is not int or meta['input_bytes']<0
                    or type(meta.get('retained_bytes')) is not int or not 0<=meta['retained_bytes']<=32768
                    or type(meta.get('truncated')) is not bool):raise RuntimeError('Diagnostic frame bounds')
            if name not in self.streams:
                if index!=0 or len(self.streams)>=8:raise RuntimeError('Diagnostic stream bounds')
                self.streams[name]={'next':0,'chunks':count,'meta':meta,'bytes':0}
            stream=self.streams[name]
            if index!=stream['next'] or count!=stream['chunks'] or meta!=stream['meta']:raise RuntimeError('Diagnostic ordering')
            stream['next']+=1;stream['bytes']+=len(text.encode());self.diagnostic_bytes+=size
            if stream['next']>count or stream['bytes']>32768 or self.diagnostic_bytes>512*1024:raise RuntimeError('Diagnostic byte budget')
            return kind
        required={'version','ok','diagnostic_only','accepted','scenario','first_failure','later_errors','evidence_complete'}
        if not required<=value.keys() or type(value['version']) is not int or value['version']!=1 or type(value['ok']) is not bool or value['diagnostic_only'] is not True or value['accepted'] is not False or type(value['evidence_complete']) is not bool:
            raise RuntimeError('Scenario result envelope')
        if not isinstance(value['scenario'],dict) or not isinstance(value['later_errors'],list) or len(value['later_errors'])>8 or any(not isinstance(x,str) or len(x)>500 for x in value['later_errors']) or value['first_failure'] is not None and not isinstance(value['first_failure'],dict):raise RuntimeError('Scenario diagnostic types')
        complete=all(s['next']==s['chunks'] and s['bytes']==s['meta']['retained_bytes'] for s in self.streams.values())
        if value['evidence_complete'] and not complete:raise RuntimeError('Incomplete diagnostics declared complete')
        if value['ok'] and (not self.reuse_verified or value['first_failure'] is not None or not value['evidence_complete'] or not self.streams):raise RuntimeError('Contradictory diagnostic completion')
        self.result=value
        return kind
