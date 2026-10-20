# Embedded update policy and atomic update bookkeeping.
record_update(){
 python3 - "$ETC/update-state.json" "$1" "${target_version:-}" "${target_digest:-}" "${target_installer:-}" <<'PY'
import json,pathlib,sys,time,os
p=pathlib.Path(sys.argv[1]);d=json.loads(p.read_text()) if p.exists() else {}
d.update(lastAttemptAt=int(time.time()),status=sys.argv[2],targetVersion=sys.argv[3])
if sys.argv[2]=='failed':d.update(failedAt=int(time.time()),failedVersion=sys.argv[3],failedDigest=sys.argv[4],failedInstaller=sys.argv[5])
elif sys.argv[2]=='updated':
 d['updatedAt']=int(time.time())
 for k in ['failedAt','failedVersion','failedDigest','failedInstaller']:d.pop(k,None)
t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(d));os.chmod(str(t),0o600);t.replace(p)
PY
}
check_update(){
 python3 - "$work" "$arch" "$BIN" "$HELPER" "${BASH_SOURCE[0]}" "$ETC/update-state.json" "$automatic" <<'PY'
import json,pathlib,sys,re,subprocess,hashlib,time,os
work=pathlib.Path(sys.argv[1]);arch,binary,helper,script,statefile,automatic=sys.argv[2:];automatic=automatic=='true';m=json.loads((work/'manifest.json').read_text());v=m.get('version','');a=m.get('assets',{}).get('linux-'+arch,{})
if not re.fullmatch(r'\d+\.\d+\.\d+',v) or a.get('url')!='/transit-node/releases/linux-'+arch or not re.fullmatch(r'[a-f0-9]{64}',a.get('sha256','')) or not isinstance(a.get('size'),int) or not 0<a['size']<=80*1024*1024:raise SystemExit('安装包清单无效或没有对应架构。')
policy=m.get('updatePolicy',{});statepath=pathlib.Path(statefile);state=json.loads(statepath.read_text()) if statepath.exists() else {};now=int(time.time());reason=''
if automatic:
 if policy.get('enabled',True) is not True:reason='控制端已暂停自动更新'
 elif os.environ.get('CT_UPDATE_DELEGATED')!='1' and now-state.get('lastCheckAt',0)<max(300,int(policy.get('intervalSeconds',3600))):reason='未到检查间隔'
 elif state.get('failedVersion')==v and state.get('failedDigest')==a['sha256'] and state.get('failedInstaller','')==m.get('installer',{}).get('sha256','') and now-state.get('failedAt',0)<max(600,int(policy.get('failureCooldownSeconds',21600))):reason='该版本失败后暂缓重试'
try:current=subprocess.run([binary,'-version'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,universal_newlines=True).stdout.strip()
except Exception:current=''
sem=lambda x:tuple(map(int,x.split('.')))
if re.fullmatch(r'\d+\.\d+\.\d+',current) and sem(v)<sem(current):reason='发布版本较旧，保留当前程序'
installer=m.get('installer');delegate=False;helper_changed=False
if installer is not None:
 if installer.get('url')!='/transit-node/install.sh' or not re.fullmatch(r'[a-f0-9]{64}',installer.get('sha256','')) or not isinstance(installer.get('size'),int) or not 0<installer['size']<=1024*1024:raise SystemExit('安装器元数据无效。')
 digest=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() if pathlib.Path(p).exists() else ''
 delegate=automatic and digest(script)!=installer['sha256'];helper_changed=digest(helper)!=installer['sha256']
if automatic and not reason and current==v and not helper_changed and not delegate:reason='已是当前版本'
if automatic and reason not in ['未到检查间隔','该版本失败后暂缓重试']:
 state['lastCheckAt']=now;state['status']=reason or 'checking';tmp=statepath.with_name(statepath.name+'.tmp');tmp.write_text(json.dumps(state));os.chmod(str(tmp),0o600);tmp.replace(statepath)
out={'skip':reason,'binaryChanged':current!=v,'delegate':delegate,'version':v,'digest':a['sha256'],'installer':installer or {}}
(work/'update-decision.json').write_text(json.dumps(out))
print(reason);print('yes' if delegate else 'no');print('yes' if current!=v else 'no');print(v);print(a['sha256']);print((installer or {}).get('sha256',''));print((installer or {}).get('size',0))
PY
}
