"""Re-embed reviewed portable helpers and pin the public launcher's digest."""
from pathlib import Path
import hashlib,re
root=Path(__file__).resolve().parents[1]/'deploy/tunnel-control'
installer=(root/'node-install.sh').read_text(encoding='utf-8')
for label,file in [('ENVIRONMENT','node-environment.sh'),('RUNTIME','node-runtime.inc.sh'),('UPDATES','node-update.inc.sh')]:
 start='# BEGIN '+label;end='# END '+label
 a=installer.index(start);b=installer.index(end,a)
 installer=installer[:a]+start+'\n'+(root/file).read_text(encoding='utf-8').rstrip()+'\n'+installer[b:]
(root/'node-install.sh').write_text(installer,encoding='utf-8',newline='\n')
launcher=(root/'node-bootstrap.sh').read_text(encoding='utf-8');a=launcher.index('# BEGIN ENVIRONMENT');b=launcher.index('# END ENVIRONMENT',a)
launcher=launcher[:a]+'# BEGIN ENVIRONMENT\n'+(root/'node-environment.sh').read_text(encoding='utf-8').rstrip()+'\n'+launcher[b:]
launcher=re.sub(r"'[a-f0-9]{64}'",repr(hashlib.sha256(installer.encode()).hexdigest()),launcher)
(root/'node-bootstrap.sh').write_text(launcher,encoding='utf-8',newline='\n')
# Use the same signed Debian archive fallback in the zero-curl first stage.
module=root/'node-installations.cjs';text=module.read_text(encoding='utf-8');match=re.search(r'const fetcher=("(?:[^"\\]|\\.)*");',text)
if match:
 import json
 fetcher=json.loads(match.group(1));environment=(root/'node-environment.sh').read_text(encoding='utf-8');a=environment.index('ct_apt_archive()');b=environment.index('ct_packages()',a);archive=environment[a:b]
 if 'ct_apt_archive()' in fetcher:
  a=fetcher.index('ct_apt_archive()');b=fetcher.index('ct_ready()',a);fetcher=fetcher[:a]+archive+fetcher[b:]
 else:fetcher=fetcher.replace('ct_ready()',archive+'ct_ready()',1)
 fetcher=fetcher.replace('install curl ca-certificates) || true','install curl ca-certificates) || ct_apt_archive curl ca-certificates || true')
 text=text[:match.start(1)]+json.dumps(fetcher,ensure_ascii=False)+text[match.end(1):];module.write_text(text,encoding='utf-8')
print('Synchronized portable helpers, initial downloader and installer SHA-256.')
