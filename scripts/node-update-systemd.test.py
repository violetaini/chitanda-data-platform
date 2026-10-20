"""End-to-end HTTPS download and rollback using disposable real systemd units."""
import pathlib,tempfile,subprocess,shutil,uuid,os,json,hashlib,ssl,http.server,threading,time

root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-update-qa-',dir='/var/tmp')).resolve();name='chitanda-qa-'+uuid.uuid4().hex[:10];unit=pathlib.Path('/etc/systemd/system')/(name+'.service');update_name=name+'-update';checks=0
assert not unit.exists() and name.startswith('chitanda-qa-')
def check(value,message):
 global checks
 assert value,message
 checks+=1
def ctl(*args,service=None,strict=True):
 result=subprocess.run(['systemctl',*args,service or name],capture_output=True,text=True)
 if strict and result.returncode:
  logs=subprocess.run(['journalctl','-u',service or name,'-n','35','--no-pager'],capture_output=True,text=True).stdout
  env_state=subprocess.run(['systemctl','show','-p','Environment',service or name],capture_output=True,text=True).stdout
  raise AssertionError((result.stderr+logs)[-3500:]+'\nENV: '+env_state)
 return result
thread=None;server=None
try:
 for cmd in ['curl','python3','bash','flock','setcap','useradd','groupadd']:assert shutil.which(cmd),'test host lacks '+cmd
 root.chmod(0o755)
 for d in ['bin','sbin','etc','state','run']: (root/d).mkdir()
 binary=root/'bin/node';helper=root/'sbin/helper';etc=root/'etc';state=root/'state';config=etc/'config.json'
 source=installer_source
 for old,new in [('/etc/systemd/system/chitanda-transit.service',str(unit)),('/usr/local/bin/chitanda-transit',str(binary)),('/usr/local/sbin/chitanda-node',str(helper)),('/etc/chitanda-transit',str(etc)),('/var/lib/chitanda-transit',str(state)),('/run/chitanda-node-install.lock',str(root/'run/install.lock'))]:source=source.replace(old,new)
 source=source.replace('chitanda-node-update',update_name).replace('chitanda-transit',name)
 helper.write_text(source);helper.chmod(0o700)
 cert=root/'ca.pem';key=root/'key.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],capture_output=True,check=True)
 def program(version,fail=False):return ('#!/bin/sh\nif [ "${1:-}" = -version ]; then echo '+version+'; exit 0; fi\n'+('exit 1\n' if fail else 'exec /usr/bin/sleep infinity\n')).encode()
 latest={'version':'3.0.1','data':program('3.0.1')};identity='f'*64
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):
   if self.headers.get('X-Node-ID')!='fixture' or self.headers.get('Authorization')!='Bearer '+identity:self.send_error(401);return
   if self.path=='/transit-node/release':
    data=json.dumps({'version':latest['version'],'assets':{'linux-amd64':{'url':'/transit-node/releases/linux-amd64','sha256':hashlib.sha256(latest['data']).hexdigest(),'size':len(latest['data'])}},'installer':{'url':'/transit-node/install.sh','sha256':hashlib.sha256(source.encode()).hexdigest(),'size':len(source.encode())},'updatePolicy':{'enabled':True,'intervalSeconds':300,'failureCooldownSeconds':21600}}).encode()
   elif self.path=='/transit-node/releases/linux-amd64':data=latest['data']
   else:self.send_error(404);return
   self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key));server.socket=context.wrap_socket(server.socket,server_side=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 config.write_text(json.dumps({'controller':'https://localhost:'+str(server.server_port),'controllerAddress':'127.0.0.1:'+str(server.server_port),'id':'fixture','token':identity,'role':'agent','dataGateway':{'domain':'preserve.example.com'}}));config.chmod(0o600)
 binary.write_bytes(program('3.0.0'));binary.chmod(0o755)
 subprocess.run(['groupadd','--system',name],check=True);subprocess.run(['useradd','--system','--gid',name,'--no-create-home','--shell','/bin/false',name],check=True)
 unit.write_text('[Unit]\nDescription=Disposable Chitanda updater QA\n[Service]\nExecStart='+str(binary)+' -config '+str(config)+'\nRestart=no\n[Install]\nWantedBy=multi-user.target\n')
 subprocess.run(['systemctl','daemon-reload'],check=True);ctl('start')
 env={**os.environ,'CURL_CA_BUNDLE':str(cert),'SSL_CERT_FILE':str(cert)}
 dropin=pathlib.Path('/etc/systemd/system')/(update_name+'.service.d');dropin.mkdir();(dropin/'qa.conf').write_text('[Service]\nEnvironment=CURL_CA_BUNDLE='+str(cert)+'\nEnvironment=SSL_CERT_FILE='+str(cert)+'\n')
 result=subprocess.run(['bash',str(helper),'setup-auto-update'],capture_output=True,text=True,env=env,timeout=30);check(result.returncode==0,'native updater timer installed: '+(result.stdout+result.stderr)[-1200:])
 subprocess.run(['systemctl','daemon-reload'],check=True)
 probe=subprocess.run(['curl','-sS','--max-time','5','https://localhost:'+str(server.server_port)+'/transit-node/release','-o','/dev/null'],env=env,capture_output=True,text=True);check(probe.returncode==0,'fixture CA works with strict local curl: '+probe.stderr)
 ctl('start',service=update_name+'.service');check(subprocess.check_output([str(binary),'-version'],text=True).strip()=='3.0.1','real systemd updater downloaded and applied authenticated HTTPS release');check(ctl('is-active',strict=False).returncode==0,'node running after real upgrade');check(json.loads(config.read_text())['dataGateway']['domain']=='preserve.example.com','business configuration preserved')
 check(ctl('is-enabled',service=update_name+'.timer',strict=False).returncode==0,'timer enabled at boot')
 pid=ctl('show','-p','MainPID','--value').stdout.strip();snapshot=json.loads((etc/'update-state.json').read_text());snapshot['lastCheckAt']=0;(etc/'update-state.json').write_text(json.dumps(snapshot));ctl('start',service=update_name+'.service');check(ctl('show','-p','MainPID','--value').stdout.strip()==pid,'same-version automatic check does not restart node')
 latest.update(version='3.0.2',data=program('3.0.2',True));snapshot['lastCheckAt']=0;(etc/'update-state.json').write_text(json.dumps(snapshot));failure=ctl('start',service=update_name+'.service',strict=False);check(failure.returncode!=0,'bad release fails native service health check');check(subprocess.check_output([str(binary),'-version'],text=True).strip()=='3.0.1' and ctl('is-active',strict=False).returncode==0,'actual binary and running service restored')
 pid=ctl('show','-p','MainPID','--value').stdout.strip();ctl('start',service=update_name+'.service');check(ctl('show','-p','MainPID','--value').stdout.strip()==pid,'failed release cooldown prevents another restart')
 print(f'PASS {checks} real-systemd automatic-update checks: HTTPS identity, timer, no-op, config preservation, health failure rollback and cooldown.')
finally:
 for service in [update_name+'.timer',update_name+'.service',name]:ctl('stop',service=service,strict=False);ctl('disable',service=service,strict=False)
 for suffix in [name+'.service',update_name+'.service',update_name+'.timer']:(pathlib.Path('/etc/systemd/system')/suffix).unlink(missing_ok=True)
 dropin=pathlib.Path('/etc/systemd/system')/(update_name+'.service.d')
 if dropin.exists():(dropin/'qa.conf').unlink(missing_ok=True);dropin.rmdir()
 subprocess.run(['systemctl','daemon-reload'],check=True)
 for service in [name,update_name+'.service',update_name+'.timer']:ctl('reset-failed',service=service,strict=False)
 subprocess.run(['userdel',name],capture_output=True);subprocess.run(['groupdel',name],capture_output=True)
 if server:server.shutdown();server.server_close()
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-update-qa-');shutil.rmtree(root)
