"""Run the panel-generated command on a bare container with a private TLS fixture."""
import pathlib,tempfile,subprocess,json,ssl,http.server,threading,hashlib,uuid,shutil

root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-command-qa-',dir='/var/tmp')).resolve();root.chmod(0o755);server=None
try:
 cert=root/'ca.pem';key=root/'key.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=node-fixture.example','-addext','subjectAltName=DNS:node-fixture.example','-keyout',str(key),'-out',str(cert)],capture_output=True,check=True)
 binary=pathlib.Path(binary_path).read_bytes();identity='a'*64;port=0;requests=[]
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def respond(self,value):
   data=value if isinstance(value,bytes) else json.dumps(value).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
  def config(self):return {'controller':'https://node-fixture.example:'+str(port),'controllerAddress':'127.0.0.1:'+str(port),'id':'fixture-node','token':identity,'role':'agent','ca':cert.read_text()}
  def manifest(self):return {'version':'2.7.2','assets':{'linux-arm64':{'url':'/transit-node/releases/linux-arm64','size':len(binary),'sha256':hashlib.sha256(binary).hexdigest()}},'installer':{'url':'/transit-node/install.sh','size':len(installer_source.encode()),'sha256':hashlib.sha256(installer_source.encode()).hexdigest()},'updatePolicy':{'enabled':True,'intervalSeconds':3600,'failureCooldownSeconds':21600}}
  def do_GET(self):
   if self.path=='/install.sh':self.respond(bootstrap_source.encode())
   elif self.path=='/transit-node/install.sh':self.respond(installer_source.encode())
   elif self.headers.get('Authorization')!='Bearer '+identity:self.send_error(401)
   elif self.path=='/transit-node/release':self.respond(self.manifest())
   elif self.path=='/transit-node/releases/linux-arm64':self.respond(binary)
   else:self.send_error(404)
  def do_POST(self):
   body=self.rfile.read(int(self.headers.get('Content-Length',0)))
   if self.path=='/transit-node/enroll':self.respond({'config':self.config(),'release':self.manifest()})
   elif self.headers.get('Authorization')!='Bearer '+identity:self.send_error(401)
   elif self.path=='/transit-node/sync':requests.append('sync');self.respond({'credentialVersion':'broker-v1','role':'agent','revision':1,'ca':cert.read_text(),'relays':[],'routes':[]})
   elif self.path=='/transit-node/uninstalled':requests.append('uninstalled');self.respond({'ok':True})
   else:self.send_error(404)
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);port=server.server_port;context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key));server.socket=context.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
 command=command_source.replace(':44443',':'+str(port));(root/'command.sh').write_text(command)
 script='''set -eu
if [ "$1" = openrc ]; then (unset SSL_CERT_FILE CURL_CA_BUNDLE; apk add --no-cache openrc); mkdir -p /run/openrc; touch /run/openrc/softlevel; cat /etc/ssl/certs/ca-certificates.crt /qa/ca.pem >/tmp/test-ca.pem; export SSL_CERT_FILE=/tmp/test-ca.pem CURL_CA_BUNDLE=/tmp/test-ca.pem; fi
if command -v curl >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then echo 'fixture unexpectedly has dependencies' >&2; exit 1; fi
mkdir -p /usr/local/share/ca-certificates
cp /qa/ca.pem /usr/local/share/ca-certificates/chitanda-qa.crt
sh /qa/command.sh
/usr/local/bin/chitanda-transit -version
test -x /usr/local/sbin/chitanda-node
test -f /etc/chitanda-transit/config.json
sleep 3
cat /var/log/chitanda-transit.log || true
cat /var/log/chitanda-node-update.log || true
/usr/local/sbin/chitanda-node status
/usr/local/sbin/chitanda-node uninstall
test ! -e /usr/local/bin/chitanda-transit
test -f /etc/chitanda-transit/config.json
echo FULL_COMMAND_PASSED
''';(root/'test.sh').write_text(script)
 results=[]
 for image,init in [('debian:12-slim','sysv'),('alpine:3.22','openrc')]:
  name='chitanda-command-qa-'+uuid.uuid4().hex[:8]
  try:
   before=requests.count('sync')
   result=subprocess.run(['docker','run','--rm','--network','host','--name',name,'--memory','768m','--pids-limit','256','-e','CURL_CA_BUNDLE=/qa/ca.pem','-e','SSL_CERT_FILE=/qa/ca.pem','-v',str(root)+':/qa:ro',image,'sh','/qa/test.sh',init],capture_output=True,text=True,timeout=150)
   row={'image':image,'init':init,'passed':result.returncode==0 and requests.count('sync')>before,'detail':(result.stdout+result.stderr)[-1800:]};results.append(row)
  finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
 print(json.dumps({'results':results,'nodeHeartbeats':requests.count('sync'),'uninstallNotifications':requests.count('uninstalled')}),flush=True)
 assert requests.count('sync')>=2,'No native node heartbeat'
 assert all(r['passed'] for r in results),json.dumps([{'image':r['image'],'detail':r['detail'][-650:]} for r in results])
finally:
 if server:server.shutdown();server.server_close()
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-command-qa-');shutil.rmtree(root)
