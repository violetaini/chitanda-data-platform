'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const quote=s=>"'"+String(s).replace(/'/g,"'\\''")+"'";
module.exports=function({dataDir,releaseDir,getState,enrollment,audit,now=Date.now}){
 const file=path.join(dataDir,'node-installations.json'),attempts=new Map();
 let tickets=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):[];
 const save=()=>{fs.writeFileSync(file+'.tmp',JSON.stringify(tickets),{mode:0o600});fs.chmodSync(file+'.tmp',0o600);fs.renameSync(file+'.tmp',file);};
 const node=id=>[...getState().nodes,...getState().relays].find(n=>n.id===id);
 function release(){
  let raw;try{raw=JSON.parse(fs.readFileSync(path.join(releaseDir,'manifest.json'),'utf8'));}catch{fail('节点安装包尚未发布，请联系管理员',503);}
  if(!/^\d+\.\d+\.\d+$/.test(raw.version))fail('节点安装包版本不正确',503);
  const assets={};
  for(const arch of ['amd64','arm64']){
   const name='linux-'+arch,v=raw.assets?.[name];if(!v)continue;
   if(v.file!=='chitanda-transit-'+name||!/^[a-f0-9]{64}$/.test(v.sha256)||!Number.isSafeInteger(v.size)||v.size<1||v.size>80*1024*1024)fail('节点安装包清单不正确',503);
   let stat;try{stat=fs.lstatSync(path.join(releaseDir,v.file));}catch{fail('节点安装包文件缺失',503);}
   if(!stat.isFile()||stat.size!==v.size)fail('节点安装包文件校验不正确',503);
   assets[name]={url:'/transit-node/releases/'+name,sha256:v.sha256,size:v.size};
  }
  if(!Object.keys(assets).length)fail('没有可用的 Linux 安装包',503);
  return {version:raw.version,assets};
 }
 function issue(id){
  const n=node(id);if(!n)fail('节点不存在',404);const config=enrollment(n,getState().relays.includes(n));
  const server=new URL(config.controller);if(server.protocol!=='https:'||server.username||server.password||server.pathname!=='/'||server.search||server.hash)fail('请配置有效的 HTTPS 控制端地址',503);
  let available,error;try{available=release();}catch(e){error=e.message;}
  tickets=tickets.filter(v=>v.until>now()&&node(v.id));if(tickets.length>=128)tickets.shift();
  const ticket=crypto.randomBytes(32).toString('hex'),until=now()+15*60000;
  tickets.push({digest:hash(ticket),id,credential:hash(n.token),until});save();
  const address=config.controllerAddress||'',resolve=address?' --server-address '+quote(address):'';
  let direct='';if(address){const m=address.match(/^(.*):(\d+)$/),ip=m?.[1].replace(/^\[|\]$/g,'');if(!m||!net.isIP(ip)||Number(m[2])!==Number(server.port||443))fail('控制端直达地址须为匹配 HTTPS 端口的 IP',503);direct=server.hostname+':'+(server.port||443)+':'+(net.isIP(ip)===6?'['+ip+']':ip);}
  const download='ct_installer=$(mktemp /tmp/chitanda-node.XXXXXXXX) && curl -fsS --proto '+quote('=https')+' --tlsv1.2'+(direct?' --resolve '+quote(direct):'')+' '+quote(server.origin+'/transit-node/install.sh')+' -o "$ct_installer"';
  const command=args=>download+' && bash "$ct_installer" '+args+'; ct_result=$?; rm -f -- "$ct_installer"; (exit "$ct_result")';
  audit('生成节点安装命令',n.name+' · 有效期 15 分钟');
  return {nodeId:id,name:n.name,config,expiresAt:new Date(until).toISOString(),available:!!available,release:available,error,commands:{install:command('install --server '+quote(server.origin)+resolve+' --ticket '+quote(ticket)),update:command('update'),uninstall:'/usr/local/sbin/chitanda-node uninstall',status:'systemctl status chitanda-transit --no-pager',logs:'journalctl -u chitanda-transit -n 50 --no-pager'}};
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
