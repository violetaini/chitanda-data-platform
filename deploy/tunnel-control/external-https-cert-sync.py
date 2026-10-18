#!/usr/bin/env python3
"""Root-owned, fixed-file bridge for an external Nginx HTTPS ingress.
Keeps DNS-managed bootstrap certificates current and reloads Nginx after the
unprivileged node atomically publishes a validated combined PEM. No shell input.
"""
import hashlib,json,os,pathlib,stat,subprocess,tempfile
os.umask(0o077)
config=json.loads(pathlib.Path('/etc/chitanda-transit/https-ingress-files.json').read_text())
for source,target in [(config['sourceCertificate'],config['bootstrapCertificate']),(config['sourceKey'],config['bootstrapKey'])]:
    data=pathlib.Path(source).read_bytes();p=pathlib.Path(target)
    if not p.exists() or p.read_bytes()!=data:
        fd,temp=tempfile.mkstemp(dir=p.parent)
        try:
            os.fchmod(fd,0o640);os.fchown(fd,0,config['nodeGid'])
            with os.fdopen(fd,'wb') as f:f.write(data)
            os.replace(temp,p)
        finally:
            if os.path.exists(temp):os.unlink(temp)
bundle=pathlib.Path(config['managedBundle'])
if not bundle.exists():raise SystemExit(0)
if not stat.S_ISREG(bundle.lstat().st_mode):raise RuntimeError('Certificate bundle must be a regular file')
digest=hashlib.sha256(bundle.read_bytes()).hexdigest();stamp=pathlib.Path('/var/lib/chitanda-https-cert-sync.sha256')
if not stamp.exists() or stamp.read_text()!=digest:
    subprocess.run([config['nginxBinary'],'-t'],check=True,capture_output=True,timeout=15)
    subprocess.run([config['nginxBinary'],'-s','reload'],check=True,capture_output=True,timeout=15)
    stamp.write_text(digest);stamp.chmod(0o600)
