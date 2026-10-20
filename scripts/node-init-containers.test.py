"""Start/stop real OpenRC, runit and SysV services inside disposable containers."""
import pathlib,tempfile,subprocess,shutil,uuid,json,concurrent.futures

root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-init-qa-',dir='/var/tmp')).resolve();root.chmod(0o755)
(root/'bootstrap.sh').write_text(bootstrap_source);(root/'runtime.sh').write_text(runtime_source)
script=r'''set -eu
sh /qa/bootstrap.sh prepare
if [ "$1" = openrc ]; then apk add --no-cache openrc; mkdir -p /run/openrc; touch /run/openrc/softlevel
elif [ "$1" = runit ]; then apt-get update >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get -y install runit >/dev/null; mkdir -p /var/service; runsvdir /var/service >/tmp/runsv.log 2>&1 &
fi
bash -s -- "$1" <<'BASH'
set -eu
source /qa/runtime.sh
INIT=$1; SERVICE=qa-node; ETC=/tmp/ct-qa/etc; STATE=/tmp/ct-qa/state; BIN=/tmp/ct-qa/node
RUNIT_DIR=/etc/sv/qa-node; RUNIT_LINK=/var/service/qa-node
UNIT=$(service_file)
mkdir -p "$ETC" "$STATE"
groupadd --system chitanda-transit; useradd --system --gid chitanda-transit --no-create-home --shell /bin/false chitanda-transit
printf '#!/bin/sh\nexec sleep 300\n' >"$BIN"; chmod 755 "$BIN"
printf '{}' >"$ETC/config.json"
write_service
service_owned
service_enable
service_start
sleep 1
service_active
service_stop
if service_active; then echo 'service is still running' >&2; exit 1; fi
service_disable
echo "PASS $INIT real service lifecycle"
BASH
'''
(root/'test.sh').write_text(script)
def run(item):
 init,image=item;name='chitanda-init-qa-'+uuid.uuid4().hex[:8]
 try:
  result=subprocess.run(['docker','run','--rm','--name',name,'--memory','768m','--pids-limit','256','-v',str(root)+':/qa:ro',image,'sh','/qa/test.sh',init],capture_output=True,text=True,timeout=120)
  return {'init':init,'image':image,'passed':result.returncode==0,'detail':(result.stdout+result.stderr)[-1800:]}
 finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
try:
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,[('openrc','alpine:3.22'),('runit','debian:12-slim'),('sysv','debian:12-slim')]))
 print(json.dumps(results),flush=True)
 assert all(r['passed'] for r in results),json.dumps([{'init':r['init'],'passed':r['passed'],'detail':r['detail'][-450:]} for r in results])
finally:
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-init-qa-');shutil.rmtree(root)
