"""Run the real installer against temporary paths and fake service/network tools.

No production service, user, firewall, certificate or directory is modified.
The caller supplies installer_source as a string (over SSH stdin in live QA).
"""
import hashlib,json,os,pathlib,shutil,subprocess,tempfile

sandbox=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-installer-test-',dir='/var/tmp')).resolve()
assert str(sandbox).startswith('/var/tmp/chitanda-installer-test-')
checks=0
def check(value,message):
 global checks
 assert value,message
 checks+=1
try:
 for name in ['etc/systemd/system','etc/chitanda-transit','var/lib/chitanda-transit','var/tmp','var/backups','usr/local/bin','usr/local/sbin','run','fakebin']:(sandbox/name).mkdir(parents=True,exist_ok=True)
 replacements=['/etc/systemd/system/chitanda-transit.service','/usr/local/sbin/chitanda-node','/usr/local/bin/chitanda-transit','/etc/chitanda-transit','/var/lib/chitanda-transit','/run/chitanda-node-install.lock','/var/tmp/chitanda-node.XXXXXXXX','/var/backups/chitanda-node.XXXXXXXX']
 source=installer_source
 for name in replacements:source=source.replace(name,str(sandbox)+name)
 script=sandbox/'installer.sh';script.write_text(source);script.chmod(0o700)
 config=sandbox/'etc/chitanda-transit/config.json';binary=sandbox/'usr/local/bin/chitanda-transit';unit=sandbox/'etc/systemd/system/chitanda-transit.service'
 fixture=sandbox/'fixture.json';statefile=sandbox/'service.json';statefile.write_text(json.dumps({'active':False,'enabled':False}))
 def payload(version='2.7.2',id='node-fixture'):
  data=f'#!/bin/bash\nprintf "%s\\n" "{version}"\n';return {'version':version,'binary':data,'id':id,'sha':hashlib.sha256(data.encode()).hexdigest()}
 fixture.write_text(json.dumps(payload()))
 fake=r'''#!/usr/bin/python3
import sys,os,json,pathlib,subprocess
root=pathlib.Path(os.environ['FAKE_ROOT']);cmd=pathlib.Path(sys.argv[0]).name;args=sys.argv[1:]
if cmd=='uname':print('Linux' if '-s' in args else os.environ.get('FAKE_ARCH','x86_64'));sys.exit(0)
if cmd in ('getent','id','groupadd','useradd'):
 if cmd=='id':print('1001')
 sys.exit(0)
if cmd=='sleep':sys.exit(0)
if cmd=='install':
 out=[];i=0
 while i<len(args):
  if args[i] in ('-o','-g'):i+=2;continue
  out.append(args[i]);i+=1
 assert str(root) in out[-1], 'installation target escaped sandbox'
 sys.exit(subprocess.run(['/usr/bin/install',*out]).returncode)
if cmd=='systemctl':
 p=root/'service.json';s=json.loads(p.read_text());op=args[0]
 if op=='is-active':sys.exit(0 if s['active'] else 3)
 if op=='is-enabled':sys.exit(0 if s['enabled'] else 1)
 if op=='stop':s['active']=False
 if op=='disable':s['enabled']=False
 if op=='enable':s['enabled']=True
 if op in ('start','restart'):
  marker=root/'fail-start'
  if marker.exists():marker.unlink();s['active']=False;p.write_text(json.dumps(s));sys.exit(1)
  s['active']=True
 p.write_text(json.dumps(s));sys.exit(0)
if cmd=='curl':
 f=json.loads((root/'fixture.json').read_text());url=next(a for a in args if a.startswith('https://'));output=pathlib.Path(args[args.index('-o')+1]);assert '--proto' in args and '--tlsv1.2' in args;assert 'a'*64 not in ' '.join(args),'long-term token exposed in argv'
 asset={'url':'/transit-node/releases/linux-'+os.environ.get('FAKE_PLATFORM','amd64'),'sha256':f['sha'],'size':len(f['binary'].encode())};release={'version':f['version'],'assets':{'linux-'+os.environ.get('FAKE_PLATFORM','amd64'):asset}}
 if url.endswith('/install.sh'):
  if (root/'fail-download').exists():sys.exit(22)
  value=(root/'installer.sh').read_text()
  if (root/'tamper-script').exists():value+='\ntouch '+str(root/'must-not-execute')+'\n'
  output.write_text(value)
 elif url.endswith('/enroll'):value={'config':{'id':f['id'],'token':'a'*64,'role':'agent','controller':'https://control.example.com','controllerAddress':'8.8.8.8:443','ca':'PUBLIC CA'},'release':release};output.write_text(json.dumps(value))
 elif url.endswith('/release'):output.write_text(json.dumps(release))
 else:
  if (root/'fail-download').exists():sys.exit(22)
  assert '/transit-node/releases/linux-' in url;output.write_text(f['binary'])
 sys.exit(0)
raise SystemExit('unexpected fake command: '+cmd)
'''
 for name in ['uname','getent','id','groupadd','useradd','install','systemctl','sleep','curl']:
  p=sandbox/'fakebin'/name;p.write_text(fake);p.chmod(0o700)
 env={**os.environ,'FAKE_ROOT':str(sandbox),'PATH':str(sandbox/'fakebin')+':'+os.environ['PATH']}
 def run(action,*extra,success=True,environment=None):
  args=['bash',str(script),action,*extra]
  if action=='install':args+=['--server','https://control.example.com','--server-address','8.8.8.8:443','--ticket','f'*64]
  r=subprocess.run(args,capture_output=True,text=True,env={**env,**(environment or {})},timeout=20)
  assert (r.returncode==0)==success,(action,r.stdout[-500:],r.stderr[-500:])
  check('a'*64 not in r.stdout+r.stderr,'node credentials do not enter installer logs')
  return r
 subprocess.run(['bash','-n',str(script)],check=True)
 if globals().get('bootstrap_source'):
  bootstrap=bootstrap_source.replace('/etc/chitanda-transit',str(sandbox)+'/etc/chitanda-transit').replace('/var/tmp/chitanda-launcher.XXXXXXXX',str(sandbox)+'/var/tmp/chitanda-launcher.XXXXXXXX').replace(hashlib.sha256(installer_source.encode()).hexdigest(),hashlib.sha256(source.encode()).hexdigest())
  launcher=sandbox/'launcher.sh';launcher.write_text(bootstrap);subprocess.run(['bash','-n',str(launcher)],check=True)
  command=['bash',str(launcher),'install','--server','https://control.example.com','--server-address','8.8.8.8:443','--ticket','f'*64]
  result=subprocess.run(command,capture_output=True,text=True,env=env,timeout=30);check(result.returncode==0 and binary.exists(),'short public launcher installs the real service in isolated paths');check(not list((sandbox/'var/tmp').iterdir()),'launcher cleans temporary script and credentials');run('uninstall','--purge')
  (sandbox/'tamper-script').touch();result=subprocess.run(command,capture_output=True,text=True,env=env,timeout=20);(sandbox/'tamper-script').unlink();check(result.returncode!=0 and not binary.exists() and not (sandbox/'must-not-execute').exists(),'launcher rejects modified script before execution')
  result=subprocess.run(['bash',str(launcher),'install','--server','http://control.example.com'],capture_output=True,text=True,env=env,timeout=20);check(result.returncode!=0 and not binary.exists(),'launcher rejects plaintext control address')
 run('install');check(binary.exists() and unit.exists(),'fresh install creates binary and unit');check(config.stat().st_mode&0o777==0o600,'private node config');check('User=chitanda-transit' in unit.read_text() and 'NoNewPrivileges=true' in unit.read_text(),'least-privilege service');check(not list((sandbox/'var/tmp').iterdir()),'temporary credentials cleaned after install')
 c=json.loads(config.read_text());c['dataGateway']={'domain':'keep.example.com'};config.write_text(json.dumps(c));cache=sandbox/'var/lib/chitanda-transit/runtime.json';cache.write_text('preserved cache');run('install');check(json.loads(config.read_text())['dataGateway']['domain']=='keep.example.com','same identity reinstall preserves gateway');check(cache.read_text()=='preserved cache','reinstall preserves cache')
 old=binary.read_bytes();oldconfig=config.read_bytes();fixture.write_text(json.dumps(payload(id='other-node')));run('install',success=False);check(config.read_bytes()==oldconfig and binary.read_bytes()==old,'different identity cannot overwrite node')
 p=payload('2.7.3');p['binary']+='touch '+str(sandbox/'must-not-execute')+'\n';fixture.write_text(json.dumps(p));run('update',success=False);check(not (sandbox/'must-not-execute').exists() and binary.read_bytes()==old,'checksum failure prevents execution and replacement')
 fixture.write_text(json.dumps(payload('2.7.3')));(sandbox/'fail-download').touch();run('update',success=False);(sandbox/'fail-download').unlink();check(binary.read_bytes()==old,'download failure preserves old binary')
 (sandbox/'fail-start').touch();run('update',success=False);check(binary.read_bytes()==old and config.read_bytes()==oldconfig,'failed service start restores binary and config');check(json.loads(statefile.read_text())['active'],'rollback restarts previous service')
 run('update');check(b'2.7.3' in binary.read_bytes(),'successful update replaces binary');check(json.loads(config.read_text())['dataGateway']['domain']=='keep.example.com','update preserves local business config')
 cert=sandbox/'etc/chitanda-transit/keep.crt';cert.write_text('certificate fixture');run('uninstall');check(config.exists() and cache.exists() and cert.exists(),'default uninstall preserves config, cache and certificate');check(not binary.exists() and not unit.exists(),'uninstall removes only owned program and service')
 run('install');run('uninstall','--purge');check(not config.exists() and not cache.exists() and cert.exists(),'explicit purge clears known config without deleting certificate')
 run('install',environment={'FAKE_ARCH':'aarch64','FAKE_PLATFORM':'arm64'});check(json.loads((sandbox/'etc/chitanda-transit/installer.json').read_text())['arch']=='arm64','architecture detection selects arm64');run('uninstall','--purge')
 run('install',success=False,environment={'FAKE_ARCH':'unsupported'});check(not binary.exists(),'unsupported architecture stops before installation')
 print(f'PASS {checks} Linux installer checks: install, repeat, update, checksum and startup rollback, uninstall preservation, purge scope and arm64 detection. All destinations confined to a temporary sandbox.')
finally:
 assert sandbox.is_relative_to(pathlib.Path('/var/tmp')) and sandbox.name.startswith('chitanda-installer-test-')
 shutil.rmtree(sandbox)
