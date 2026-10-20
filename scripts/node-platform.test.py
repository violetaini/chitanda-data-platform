"""Validate service templates without starting any host service."""
import pathlib,tempfile,subprocess,shutil,shlex
root=pathlib.Path(tempfile.mkdtemp(prefix='chitanda-platform-qa-',dir='/var/tmp')).resolve()
checks=0
try:
 for init in ['systemd','openrc','runit','sysv']:
  path=root/init;path.mkdir();script=path/'render.sh';unit=path/'service'
  script.write_text('set -eu\n'+runtime_source+'\n'+f'INIT={init}\nSERVICE=qa-node\nBIN={path}/bin\nETC={path}/etc\nSTATE={path}/state\nUNIT={unit}\nRUNIT_DIR={path}/runit\nwrite_service\n')
  result=subprocess.run(['bash',str(script)],capture_output=True,text=True);assert result.returncode==0,(init,result.stderr)
  assert 'Managed by Chitanda node installer' in unit.read_text();checks+=1
  if init!='systemd':subprocess.run(['sh','-n',str(unit)],check=True);checks+=1
  assert str(path) in unit.read_text();checks+=1
 print(f'PASS {checks} service-template checks: systemd / OpenRC / runit / SysV.')
finally:
 assert root.is_relative_to(pathlib.Path('/var/tmp')) and root.name.startswith('chitanda-platform-qa-');shutil.rmtree(root)
