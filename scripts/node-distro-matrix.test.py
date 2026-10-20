"""Provision dependencies in disposable official Linux containers.

Call over SSH with bootstrap_source; no host service/config is mounted.
"""
import pathlib,tempfile,subprocess,concurrent.futures,json,shutil,uuid,time

root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-distro-qa-',dir='/var/tmp')).resolve()
images=['debian:10-slim','debian:11-slim','debian:12-slim','debian:13-slim','ubuntu:18.04','ubuntu:20.04','ubuntu:22.04','ubuntu:24.04','alpine:3.20','alpine:3.22','rockylinux:8-minimal','rockylinux:9-minimal','almalinux:9-minimal','fedora:latest','opensuse/tumbleweed:latest','archlinux:base']
prefix='chitanda-distro-qa-'+uuid.uuid4().hex[:8]
(root/'bootstrap.sh').write_text(bootstrap_source);(root/'bootstrap.sh').chmod(0o644);root.chmod(0o755)
def run(item):
 index,image=item;name=prefix+'-'+str(index);started=time.time()
 try:
  pull=subprocess.run(['docker','pull',image],capture_output=True,text=True,timeout=240)
  if pull.returncode:return {'image':image,'status':'image-unavailable','detail':pull.stderr[-250:]}
  result=subprocess.run(['docker','run','--rm','--name',name,'--memory','768m','--pids-limit','256','--cpus','1','-v',str(root)+':/qa:ro',image,'sh','-c','sh /qa/bootstrap.sh prepare && python3 -c "import sys; print(sys.version.split()[0])" && bash --version | head -1'],capture_output=True,text=True,timeout=480)
  summary={'image':image,'status':'passed' if result.returncode==0 else 'failed','seconds':round(time.time()-started),'detail':(result.stdout+result.stderr)[-1200:]}
  (root/(str(index)+'.log')).write_text(result.stdout+result.stderr)
  return summary
 except subprocess.TimeoutExpired:return {'image':image,'status':'timeout'}
 finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
try:
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  results=[]
  for future in concurrent.futures.as_completed([pool.submit(run,item) for item in enumerate(images)]):
   row=future.result();results.append(row);print(json.dumps(row),flush=True)
 print(json.dumps({'summary':{'passed':sum(r['status']=='passed' for r in results),'total':len(results)},'results':results}),flush=True)
 assert all(r['status'] in ['passed','image-unavailable'] for r in results),'Distribution preparation failed'
finally:
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-distro-qa-')
 shutil.rmtree(root)
