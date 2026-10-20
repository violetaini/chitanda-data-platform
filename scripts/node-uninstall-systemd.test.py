"""Exercise uninstall using an isolated, real systemd sleep service.

Run over SSH with installer_source / bootstrap_source supplied by the caller.
Never targets the production service, account, program, config or certificate.
"""
import pathlib,tempfile,subprocess,shutil,json,os,hashlib,uuid

root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-uninstall-qa-',dir='/var/tmp')).resolve()
service='chitanda-uninstall-qa-'+uuid.uuid4().hex[:12]
unit=pathlib.Path('/etc/systemd/system')/(service+'.service')
assert unit.parent==pathlib.Path('/etc/systemd/system') and not unit.exists()
binary=root/'bin/chitanda-transit';helper=root/'sbin/chitanda-node';etc=root/'etc';state=root/'state';checks=0
def check(value,message):
 global checks
 assert value,message
 checks+=1
def ctl(*args,check=True):return subprocess.run(['systemctl',*args,service],capture_output=True,text=True,check=check)
try:
 for p in [binary.parent,helper.parent,etc,state,root/'run',root/'fakebin']:p.mkdir()
 source=installer_source.replace('if command -v python3 >/dev/null && [[ -f $ETC/config.json ]]; then','if false; then')
 source=source.replace('SERVICE=chitanda-transit','SERVICE='+service).replace('chitanda-node-update',service+'-update')
 for old,new in [('/etc/systemd/system/chitanda-transit.service',str(unit)),('/usr/local/bin/chitanda-transit',str(binary)),('/usr/local/sbin/chitanda-node',str(helper)),('/etc/chitanda-transit',str(etc)),('/var/lib/chitanda-transit',str(state)),('/run/chitanda-node-install.lock',str(root/'run/install.lock'))]:source=source.replace(old,new)
 script=root/'installer.sh';script.write_text(source);script.chmod(0o700)
 config=etc/'config.json';config.write_text(json.dumps({'controller':'https://controller.example.com','id':'qa-node','token':'f'*64}));config.chmod(0o600)
 cert=etc/'private.crt';cert.write_text('retained certificate fixture');cache=state/'runtime.json';cache.write_text('retained cache');external=root/'external-gateway.conf';external.write_text('untouched')
 def provision(marker=True):
  binary.write_text('#!/bin/bash\nexec /usr/bin/sleep infinity\n');binary.chmod(0o700)
  unit.write_text(f'[Unit]\nDescription=Temporary Chitanda uninstall QA\n[Service]\nExecStart={binary} -config {config}\n[Install]\nWantedBy=multi-user.target\n')
  if marker:(etc/'installer.json').write_text('{"version":"fixture"}');helper.write_text(source);helper.chmod(0o700)
  subprocess.run(['systemctl','daemon-reload'],check=True);ctl('enable');ctl('start');check(ctl('is-active',check=False).returncode==0,'temporary service is running before uninstall')
 provision()
 result=subprocess.run(['bash',str(helper),'uninstall'],capture_output=True,text=True,timeout=30);check(result.returncode==0,'installed helper uninstalls itself successfully')
 check(ctl('is-active',check=False).returncode!=0 and ctl('is-enabled',check=False).returncode!=0,'real systemd service stopped and disabled')
 check(not binary.exists() and not helper.exists() and not unit.exists(),'program, helper and unit removed')
 check(config.exists() and cache.exists() and cert.exists() and external.read_text()=='untouched','configuration, cache, certificate and external adapter preserved')
 provision(marker=False)
 # Download fixture changes only transport; the real reviewed launcher and
 # full uninstall code run, and all systemctl calls use the real systemd.
 curl=root/'fakebin/curl';curl.write_text('#!/bin/bash\nwhile [[ $# -gt 0 ]]; do if [[ $1 == -o ]]; then cp '+str(script)+' "$2"; exit; fi; shift; done; exit 22\n');curl.chmod(0o700)
 bootstrap=bootstrap_source.replace('/etc/chitanda-transit',str(etc)).replace('/var/tmp/chitanda-launcher.XXXXXXXX',str(root/'launcher.XXXXXXXX')).replace(hashlib.sha256(installer_source.encode()).hexdigest(),hashlib.sha256(source.encode()).hexdigest())
 launcher=root/'launcher.sh';launcher.write_text(bootstrap)
 result=subprocess.run(['bash',str(launcher),'uninstall'],capture_output=True,text=True,env={**os.environ,'PATH':str(root/'fakebin')+':'+os.environ['PATH']},timeout=30)
 check(result.returncode==0,'public launcher uninstalls legacy deployment without helper or marker')
 check(ctl('is-active',check=False).returncode!=0 and not unit.exists() and not binary.exists(),'legacy service and program actually removed')
 check(config.exists() and cert.exists() and cache.exists(),'legacy data retained')
 result=subprocess.run(['bash',str(script),'uninstall'],capture_output=True,text=True,timeout=30);check(result.returncode==0,'repeat default uninstall is safe')
 provision(marker=False);unit.write_text(unit.read_text().replace('ExecStart=','ExecStart=/unknown '))
 result=subprocess.run(['bash',str(script),'uninstall'],capture_output=True,text=True,timeout=30)
 check(result.returncode!=0 and binary.exists() and ctl('is-active',check=False).returncode==0,'unrecognized unit is refused without stopping it')
 print(f'PASS {checks} real-systemd uninstall checks: helper, legacy launcher, stop/disable/remove, retained data, repeat and foreign-unit refusal. Production nodes untouched.')
finally:
 assert service.startswith('chitanda-uninstall-qa-') and unit.name==service+'.service'
 ctl('stop',check=False);ctl('disable',check=False);unit.unlink(missing_ok=True);subprocess.run(['systemctl','daemon-reload'],check=True);ctl('reset-failed',check=False)
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-uninstall-qa-')
 shutil.rmtree(root)
