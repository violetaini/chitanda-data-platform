'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const quote=s=>"'"+String(s).replace(/'/g,"'\\''")+"'";
module.exports=function({dataDir,releaseDir,getState,getReport=()=>({online:false}),enrollment,audit,now=Date.now}){
 const file=path.join(dataDir,'node-installations.json'),attempts=new Map();
 let tickets=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):[];
 const save=()=>{fs.writeFileSync(file+'.tmp',JSON.stringify(tickets),{mode:0o600});fs.chmodSync(file+'.tmp',0o600);fs.renameSync(file+'.tmp',file);};
 const node=id=>[...getState().nodes,...getState().relays].find(n=>n.id===id);
 function release(){
  let raw;try{raw=JSON.parse(fs.readFileSync(path.join(releaseDir,'manifest.json'),'utf8'));}catch{fail('节点安装包尚未发布，请联系管理员',503);}
  if(!/^\d+\.\d+\.\d+$/.test(raw.version))fail('节点安装包版本不正确',503);
  const assets={};
  for(const arch of ['amd64','arm64','armv7','386','riscv64','loong64','ppc64le','s390x']){
   const name='linux-'+arch,v=raw.assets?.[name];if(!v)continue;
   if(v.file!=='chitanda-transit-'+name||!/^[a-f0-9]{64}$/.test(v.sha256)||!Number.isSafeInteger(v.size)||v.size<1||v.size>80*1024*1024)fail('节点安装包清单不正确',503);
   let stat;try{stat=fs.lstatSync(path.join(releaseDir,v.file));}catch{fail('节点安装包文件缺失',503);}
   if(!stat.isFile()||stat.size!==v.size)fail('节点安装包文件校验不正确',503);
   assets[name]={url:'/transit-node/releases/'+name,sha256:v.sha256,size:v.size};
  }
  if(!Object.keys(assets).length)fail('没有可用的 Linux 安装包',503);
  const installerFile=path.join(__dirname,'node-install.sh'),data=fs.readFileSync(installerFile);
  return {version:raw.version,assets,installer:{url:'/transit-node/install.sh',size:data.length,sha256:hash(data)},updatePolicy:getState().settings?.nodeUpdates||{enabled:true,intervalSeconds:3600,failureCooldownSeconds:21600}};
 }
 function issue(id,requestedAction){
  if(requestedAction!==undefined&&!['install','uninstall'].includes(requestedAction))fail('节点操作不正确');
  const n=node(id);if(!n)fail('节点不存在',404);const config=enrollment(n,getState().relays.includes(n));
  const server=new URL(config.controller);if(server.protocol!=='https:'||server.username||server.password||server.pathname!=='/'||server.search||server.hash)fail('请配置有效的 HTTPS 控制端地址',503);
  let available,error;try{available=release();}catch(e){error=e.message;}
  tickets=tickets.filter(v=>v.until>now()&&node(v.id));if(tickets.length>=128)tickets.shift();
  const installed=n.installation?.status==='installed',online=!!getReport(id).online,action=requestedAction||(installed&&online?'uninstall':'install'),install=action==='install',ticket=install?crypto.randomBytes(32).toString('hex'):'',until=install?now()+15*60000:null;
  if(install){tickets.push({digest:hash(ticket),id,credential:hash(n.token),until});save();}
  const address=config.controllerAddress||'',resolve=address?' --server-address '+quote(address):'';
  let direct='';if(address){const m=address.match(/^(.*):(\d+)$/),ip=m?.[1].replace(/^\[|\]$/g,'');if(!m||!net.isIP(ip)||Number(m[2])!==Number(server.port||443))fail('控制端直达地址须为匹配 HTTPS 端口的 IP',503);direct=server.hostname+':'+(server.port||443)+':'+(net.isIP(ip)===6?'['+ip+']':ip);}
  const github='https://raw.githubusercontent.com/violetaini/chitanda-data-platform/main/deploy/tunnel-control/node-bootstrap.sh';
  const fetcher="set -eu\n[ \"$(id -u)\" = 0 ] || { echo \"请先执行 sudo -i\" >&2; exit 1; }\nct_apt_archive() {\n [ -r /etc/os-release ] || return 1\n . /etc/os-release\n [ \"${ID:-}\" = debian ] || return 1\n case ${VERSION_ID:-} in 10) ct_suite=buster;; 11) ct_suite=bullseye;; *) return 1;; esac\n echo \"当前软件源不可用，尝试 Debian 官方归档（仅临时来源，保留签名验证）……\"\n ct_apt_dir=$(mktemp -d /var/tmp/chitanda-apt.XXXXXXXX) || return 1\n chmod 755 \"$ct_apt_dir\"; mkdir -p \"$ct_apt_dir/lists/partial\"\n printf 'deb http://archive.debian.org/debian %s main\\ndeb http://archive.debian.org/debian-security %s-security main\\n' \"$ct_suite\" \"$ct_suite\" >\"$ct_apt_dir/sources.list\"\n if [ \"$ct_suite\" = buster ]; then printf 'deb http://archive.debian.org/debian buster main\\ndeb http://archive.debian.org/debian-security buster/updates main\\n' >\"$ct_apt_dir/sources.list\"; fi\n ct_apt_result=0\n env DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist=\"$ct_apt_dir/sources.list\" -o Dir::Etc::sourceparts=- -o Dir::State::lists=\"$ct_apt_dir/lists\" -o Acquire::Retries=3 update &&\n env DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist=\"$ct_apt_dir/sources.list\" -o Dir::Etc::sourceparts=- -o Dir::State::lists=\"$ct_apt_dir/lists\" -o DPkg::Lock::Timeout=120 -y --no-install-recommends install \"$@\" || ct_apt_result=$?\n rm -rf -- \"$ct_apt_dir\"\n return \"$ct_apt_result\"\n}\nct_ready(){ command -v curl >/dev/null 2>&1 && { [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || [ -s /etc/ssl/ca-bundle.pem ]; }; }\nif ! ct_ready; then\n ct_curl=curl; command -v curl >/dev/null 2>&1 && ct_curl=\n ct_try=0\n until ct_ready; do\n  ct_try=$((ct_try+1)); [ \"$ct_try\" -le 3 ] || { echo \"无法安装 curl，请检查软件源\" >&2; exit 1; }\n  if command -v apt-get >/dev/null 2>&1; then (export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=120 update && apt-get -o DPkg::Lock::Timeout=120 -y install $ct_curl ca-certificates) || ct_apt_archive $ct_curl ca-certificates || true\n  elif command -v dnf >/dev/null 2>&1; then dnf -y install $ct_curl ca-certificates || true\n  elif command -v microdnf >/dev/null 2>&1; then microdnf -y install $ct_curl ca-certificates || true\n  elif command -v yum >/dev/null 2>&1; then yum -y install $ct_curl ca-certificates || true\n  elif command -v apk >/dev/null 2>&1; then apk add --no-cache $ct_curl ca-certificates || true\n  elif command -v zypper >/dev/null 2>&1; then zypper -n install $ct_curl ca-certificates || true\n  elif command -v pacman >/dev/null 2>&1; then pacman -S --needed --noconfirm $ct_curl ca-certificates || true\n  elif command -v xbps-install >/dev/null 2>&1; then xbps-install -Sy $ct_curl ca-certificates || true\n  else echo \"请安装 curl 与 CA 证书后重试\" >&2; exit 1; fi\n done\nfi\nct_url=$1; ct_resolve=$2; shift 2\nct_script=$(mktemp); trap 'ct_result=$?; rm -f -- \"$ct_script\"; exit \"$ct_result\"' 0\nct_get(){ curl -q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 180 \"$@\" \"$ct_url\" -o \"$ct_script\"; }\nif [ -n \"$ct_resolve\" ]; then ct_get --noproxy '*' --resolve \"$ct_resolve\"; else ct_get; fi\nsh \"$ct_script\" \"$@\"";
  const launch=(url,args,origin=false)=>'sh -c '+quote(fetcher)+' sh '+quote(url)+' '+quote(origin?direct:'')+' '+args;
  const short=(url,args,origin=false)=>'CT_SOURCE='+quote(url)+' sh -c '+quote('s=$(curl -qfsSL --retry 3 --connect-timeout 10 --max-time 180 --proto =https --proto-redir =https'+(origin&&direct?' --noproxy '+quote('*')+' --resolve '+quote(direct):'')+' "$CT_SOURCE") && [ -n "$s" ] && exec sh -c "$s" sh "$@"')+' sh '+args;
  const installArgs='install --server '+quote(server.origin)+' --ticket '+quote(ticket);
  if(install)audit(installed?'生成节点重新安装命令':'生成节点安装命令',n.name+' · 有效期 15 分钟');
  return {nodeId:id,name:n.name,installed,online,action,expiresAt:until?new Date(until).toISOString():null,available:!install||!!available,error:install?error:undefined,repository:'https://github.com/violetaini/chitanda-data-platform',commands:!install?{github:short(github,'uninstall'),origin:short(server.origin+'/install.sh','uninstall',true)}:{github:short(github,installArgs+resolve),origin:short(server.origin+'/install.sh',installArgs+resolve,true)},compatCommands:!install?{github:launch(github,'uninstall'),origin:launch(server.origin+'/install.sh','uninstall',true)}:{github:launch(github,installArgs+resolve),origin:launch(server.origin+'/install.sh',installArgs+resolve,true)}};
 }
 function claim(input,ip){
  if(!net.isIP(ip))fail('节点来源地址不正确',403);
  const cutoff=now()-60000;for(const [key,v] of attempts)if(v.since<cutoff)attempts.delete(key);
  if(attempts.size>=2048&&!attempts.has(ip))fail('请求较多，请稍后重试',429);
  const a=attempts.get(ip)||{since:now(),count:0};a.count++;attempts.set(ip,a);if(a.count>12)fail('请求较多，请稍后重试',429);
  if(Object.keys(input).some(k=>k!=='ticket')||!/^[a-f0-9]{64}$/.test(input.ticket||''))fail('安装凭据无效或已到期',401);
  const record=tickets.find(v=>v.digest===hash(input.ticket)),n=record&&node(record.id);
  if(!record||record.until<=now()||!n||record.credential!==hash(n.token)||record.ip&&record.ip!==ip)fail('安装凭据无效、已到期或已被使用',401);
  const manifest=release();if(!record.ip)audit('节点安装凭据已领取',n.name);record.ip=ip;save();
  // A repeat from the same server recovers a lost response within the lease.
  return {config:enrollment(n,getState().relays.includes(n)),release:manifest};
 }
 function asset(platform){const manifest=release(),entry=manifest.assets[platform];if(!entry)fail('不支持此节点架构',404);return {file:path.join(releaseDir,'chitanda-transit-'+platform),...entry};}
 return {issue,claim,release,asset};
};
