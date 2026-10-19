'use strict';
// Control-plane DNS only. Cloud provider credentials remain inside DNS Manager.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),https=require('node:https'),net=require('node:net');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const fqdn=value=>{const s=String(value||'').trim().toLowerCase().replace(/\.$/,'');if(s.length>253||!s.includes('.')||!s.split('.').every(v=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v)))fail('请填写有效域名');return s;};
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const writePrivate=(file,value)=>{fs.writeFileSync(file+'.tmp',JSON.stringify(value,null,2),{mode:0o600});fs.chmodSync(file+'.tmp',0o600);fs.renameSync(file+'.tmp',file);};
function providerInput(input,previous={}){
 let url;try{url=new URL(input.baseURL);}catch{fail('DNS 管理地址不正确');}
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/'||net.isIP(url.hostname))fail('DNS 管理地址须为 HTTPS 域名根地址');
 const uid=Number(input.uid),zoneId=Number(input.zoneId),zone=fqdn(input.zone),apiKey=String(input.apiKey||previous.apiKey||'');
 if(!Number.isSafeInteger(uid)||uid<1||!Number.isSafeInteger(zoneId)||zoneId<1||!apiKey||apiKey.length>256)fail('请填写 DNS API 用户、密钥及区域 ID');
 return {baseURL:url.origin,uid,zoneId,zone,apiKey};
}
function client(config,fetcher=fetch){
 async function call(endpoint,fields={}){
  const timestamp=String(Math.floor(Date.now()/1000)),sign=crypto.createHash('md5').update(String(config.uid)+timestamp+config.apiKey).digest('hex');
  let response,value;try{
   response=await fetcher(config.baseURL+'/api/'+endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...fields,uid:String(config.uid),timestamp,sign})});
   const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;if(size>1048576)throw Error('large response');chunks.push(chunk);}value=JSON.parse(Buffer.concat(chunks).toString());
  }catch{fail('DNS 管理服务暂时不可用，请检查连接配置',502);}
  if(!response.ok||value.code!==undefined&&value.code!==0)fail('DNS 管理 API 请求失败，请检查 API 权限及区域配置',502);
  return value;
 }
 const relative=name=>{if(!name.endsWith('.'+config.zone))fail('域名须位于已接入区域下');return name.slice(0,-config.zone.length-1);};
 return {
  async zone(){const result=await call('domain/'+config.zoneId);if(result.data?.name!==config.zone)fail('DNS 区域 ID 与域名不一致');const lines=result.data.recordLine||[];if(!['default_view','Abroad'].every(id=>lines.some(v=>v.id===id)))fail('DNS 区域不支持默认及境外线路');return {zone:config.zone,minTTL:Number(result.data.minTTL)||1};},
  async records(name){let rows=[],offset=0;for(let page=0;page<20;page++){const v=await call('record/data/'+config.zoneId,{subdomain:relative(name),offset:String(offset),limit:'100'});if(!Array.isArray(v.rows)||!Number.isInteger(v.total))fail('DNS 记录响应不完整',502);rows.push(...v.rows);if(rows.length>=v.total)return rows;offset+=100;}fail('该域名记录过多，请先整理',409);},
  async add(record){await call('record/add/'+config.zoneId,{name:record.Name,type:record.Type,value:record.Value.join(','),line:record.Line,ttl:String(record.TTL),weight:String(record.Weight??1),mx:String(record.MX??1),remark:record.Remark||''});},
  async remove(record){await call('record/delete/'+config.zoneId,{recordid:record.RecordId});},
  async update(record,previous){await call('record/update/'+config.zoneId,{recordid:previous.RecordId,name:record.Name,type:record.Type,value:record.Value.join(','),line:record.Line,ttl:String(record.TTL),weight:String(record.Weight??1),mx:String(record.MX??1),remark:record.Remark||''});},
  async status(record){await call('record/status/'+config.zoneId,{recordid:record.RecordId,status:record.Status});},relative
 };
}
function inspectTLS(node,name){
 if(net.isIP(node.host)!==4||/^(127|10|0|169\.254|192\.168)\.|^172\.(1[6-9]|2\d|3[01])\./.test(node.host))fail('节点公网 IPv4 尚未就绪');
 return new Promise((resolve,reject)=>{
  // A shared HTTPS agent pools by hostname, not this fixed-IP lookup. Disable
  // pooling and session reuse so each region is checked on its own connection.
  const req=https.request({agent:false,hostname:name,servername:name,port:443,path:'/',method:'HEAD',family:4,autoSelectFamily:false,signal:AbortSignal.timeout(8000),minVersion:'TLSv1.3',rejectUnauthorized:true,lookup:(_host,_options,callback)=>callback(null,node.host,4)},res=>res.resume());
  req.on('socket',socket=>socket.once('secureConnect',()=>{try{const cert=new crypto.X509Certificate(socket.getPeerCertificate().raw);if(!cert.checkHost(name)||Date.parse(cert.validTo)<Date.now()+86400000)throw Error();resolve({nodeId:node.id,host:node.host,dnsNames:cert.subjectAltName,notAfter:new Date(cert.validTo).toISOString(),fingerprint:cert.fingerprint256});req.destroy();}catch{reject(Object.assign(Error('节点证书未覆盖业务域名或即将到期'),{status:400}));req.destroy();}}));
  req.on('error',()=>reject(Object.assign(Error('节点 HTTPS 或证书验证失败：'+node.name),{status:400})));req.setTimeout(8000,()=>req.destroy());req.end();
 });
}
const recordShape=r=>({Name:r.Name,Type:r.Type,Value:(Array.isArray(r.Value)?r.Value:[r.Value]).map(v=>String(v).replace(/\.$/,'')).sort(),Line:r.Line,TTL:Number(r.TTL),Status:String(r.Status??'1'),Weight:Number(r.Weight??1),Remark:r.Remark||'',MX:r.MX??null});
const recordsEqual=(a,b)=>['Name','Type','Line','TTL','Status','Weight'].every(k=>recordShape(a)[k]===recordShape(b)[k])&&JSON.stringify(recordShape(a).Value)===JSON.stringify(recordShape(b).Value);
module.exports=function({dataDir,getState,save,audit,probe=inspectTLS,makeClient=client}){
 const file=path.join(dataDir,'dns-provider.json'),plans=new Map();let busy=false;
 const config=()=>fs.existsSync(file)?providerInput(JSON.parse(fs.readFileSync(file,'utf8'))):null;
 const getBinding=id=>{const b=(getState().domains||[]).find(v=>v.id===id);if(!b)fail('域名绑定不存在',404);return b;};
 function routes(binding){const s=getState(),nodes=[...s.nodes,...s.relays];return ['mainlandRouteId','internationalRouteId'].map(k=>{const r=s.routes.find(r=>r.id===binding[k]),node=nodes.find(n=>n.id===r?.source);if(!r||!r.enabled||!node?.ingress||!net.isIP(node.host))fail('域名绑定的线路或 HTTPS 入口尚未就绪',409);if(node.ingress.domain!==binding.domain)fail('业务域名须与两端已部署的 HTTPS / SSL 域名一致',409);return {route:r,node};});}
 function summary(){const c=config();return {configured:!!c,...(c?{baseURL:c.baseURL,uid:c.uid,zoneId:c.zoneId,zone:c.zone}:{}),bindings:(getState().domains||[]).map(b=>({...b,regions:['国内 / 默认','国际 / 境外'].map((region,i)=>{const r=getState().routes.find(r=>r.id===b[i?'internationalRouteId':'mainlandRouteId']),n=[...getState().nodes,...getState().relays].find(n=>n.id===r?.source);return {region,routeId:r?.id,nodeId:n?.id,nodeName:n?.name,host:n?.host};})}))};}
 async function configure(input){if(busy)fail('DNS 正在发布，请稍后再修改连接',409);busy=true;try{const previous=config()||{},next=providerInput(input,previous);if((getState().domains||[]).length&&previous.zone&&(next.zone!==previous.zone||next.zoneId!==previous.zoneId||next.baseURL!==previous.baseURL))fail('已有域名绑定时不能切换 DNS 区域或服务',409);await makeClient(next).zone();writePrivate(file,next);audit('接入 DNS 管理',next.baseURL+' · '+next.zone);return summary();}finally{busy=false;}}
 function create(input){const c=config();if(!c)fail('请先接入 DNS 管理');const domain=fqdn(input.domain);if(!domain.endsWith('.'+c.zone)||domain===c.zone)fail('业务域名须为接入区域下的子域名');if((getState().domains||[]).some(b=>b.domain===domain))fail('该业务域名已绑定',409);if((getState().domains||[]).length>=64)fail('最多配置 64 个业务域名');const id=crypto.randomBytes(8).toString('hex'),ttl=Number(input.ttl??60);if(!Number.isInteger(ttl)||ttl<60||ttl>3600)fail('TTL 应为 60–3600 秒');const b={id,domain,cname:'ct-'+id+'.tunnel.'+c.zone,mainlandRouteId:String(input.mainlandRouteId),internationalRouteId:String(input.internationalRouteId),ttl,status:'draft',createdAt:new Date().toISOString()};const rs=routes(b);if(rs[0].node.id===rs[1].node.id)fail('国内与国际须选择不同源节点');getState().domains||=[];getState().domains.push(b);audit('绑定业务域名',domain);return b;}
 async function plan(id){
  const binding=getBinding(id),c=config();if(!c)fail('DNS 管理尚未配置');const api=makeClient(c),rs=routes(binding),zone=await api.zone();if(binding.ttl<zone.minTTL)fail('TTL 小于 DNS 区域最低要求');
  const certificate=await Promise.all(rs.map(({node})=>probe(node,binding.domain)));
  const names=[binding.domain,binding.cname],current=(await Promise.all(names.map(n=>api.records(n)))).flat();
  const marker='Chitanda datahub '+binding.id,desired=[{Name:api.relative(binding.domain),Type:'CNAME',Value:[binding.cname],Line:'default_view',TTL:binding.ttl,Status:'1',Weight:1,Remark:marker},...rs.map(({node},i)=>({Name:api.relative(binding.cname),Type:'A',Value:[node.host],Line:i?'Abroad':'default_view',TTL:binding.ttl,Status:'1',Weight:1,Remark:marker}))];
  for(const r of current){const own=r.Remark===marker,adopt=binding.status==='draft'&&r.Name===api.relative(binding.domain)&&r.Type==='A'&&['default_view','Abroad'].includes(r.Line)&&String(r.Status)==='1'&&(Array.isArray(r.Value)?r.Value:[r.Value]).every(ip=>rs[r.Line==='Abroad'?1:0].node.host===ip);if(!own&&!adopt)fail('发现未由此绑定管理的 DNS 记录，拒绝覆盖：'+r.Name+' / '+r.Type,409);}
  const slot=(a,b)=>a.Name===b.Name&&a.Type===b.Type&&a.Line===b.Line;
  const remove=current.filter(r=>!desired.some(d=>slot(r,d))),add=desired.filter(d=>!current.some(r=>slot(r,d))),updates=desired.flatMap(next=>{const previous=current.find(r=>slot(r,next));return previous&&!recordsEqual(previous,next)?[{next,previous}]:[];}),fingerprint=digest({current:current.map(r=>({id:r.RecordId,...recordShape(r)})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))),desired});
  const result={bindingId:id,domain:binding.domain,cname:binding.cname,certificate,records:desired,changes:{remove:remove.map(recordShape),add:add.map(recordShape),update:updates.map(v=>({from:recordShape(v.previous),to:recordShape(v.next)}))},fingerprint};plans.set(id,{fingerprint,until:Date.now()+300000});return {result,api,current,remove,add,updates,binding};
 }
 async function publish(id,fingerprint){
  if(busy)fail('另一项 DNS 发布正在执行',409);const approved=plans.get(id);if(!approved||approved.until<Date.now()||approved.fingerprint!==fingerprint)fail('请先预览最新 DNS 变更',409);busy=true;let work;
  try{work=await plan(id);if(work.result.fingerprint!==fingerprint)fail('DNS 记录或节点已变化，请重新预览',409);
   const {api,binding,remove,add,updates}=work,removed=[],added=[],updated=[];const backup=path.join(dataDir,'dns-backup-'+id+'-'+Date.now()+'.json');writePrivate(backup,{domain:binding.domain,cname:binding.cname,records:work.current});
   try{
    // Make regional targets available before replacing the business hostname.
    for(const r of add.filter(r=>r.Type==='A')){await api.add(r);added.push(r);}
    for(const u of updates){await api.update(u.next,u.previous);updated.push(u);}
    for(const r of remove){await api.remove(r);removed.push(r);}
    for(const r of add.filter(r=>r.Type!=='A')){await api.add(r);added.push(r);}
    const actual=(await Promise.all([binding.domain,binding.cname].map(n=>api.records(n)))).flat();if(actual.length!==work.result.records.length||!work.result.records.every(d=>actual.some(r=>recordsEqual(r,d))))throw Error('verification failed');
   }catch{
    // Reconcile against the snapshot even if the provider committed a request
    // whose response was lost. A client-side success journal alone is unsafe.
    let restored=true;try{
     const sameSlot=(a,b)=>a.Name===b.Name&&a.Type===b.Type&&a.Line===b.Line;
     let now=(await Promise.all([binding.domain,binding.cname].map(n=>api.records(n)))).flat();
     for(const r of now.filter(r=>r.Remark==='Chitanda datahub '+id&&!work.current.some(old=>sameSlot(old,r))))await api.remove(r);
     now=(await Promise.all([binding.domain,binding.cname].map(n=>api.records(n)))).flat();
     for(const old of work.current){const current=now.find(r=>sameSlot(old,r));if(!current)await api.add(old);else if(!recordsEqual(old,current)){if(current.RecordId!==old.RecordId&&current.Remark!=='Chitanda datahub '+id)throw Error('concurrent change');await api.update(old,current);}}
     const after=(await Promise.all([binding.domain,binding.cname].map(n=>api.records(n)))).flat();restored=after.length===work.current.length&&work.current.every(r=>after.some(n=>recordsEqual(r,n)));
    }catch{restored=false;}
    binding.lastError=restored?'发布未完成，已恢复原解析':'发布及回退未完成，请检查 DNS 备份';save();fail(binding.lastError,502);
   }
   binding.status='published';binding.publishedAt=new Date().toISOString();binding.lastCertificateCheck=work.result.certificate;delete binding.lastError;plans.delete(id);audit('发布域名解析',binding.domain+' → '+binding.cname);return work.result;
  }finally{busy=false;}
 }
 function remove(id){const b=getBinding(id);if(b.status==='published')fail('已发布域名保留接入记录，避免误删生产解析',409);getState().domains=getState().domains.filter(v=>v.id!==id);plans.delete(id);audit('移除域名草稿',b.domain);}
 return {summary,configure,create,preview:async id=>(await plan(id)).result,publish,remove};
};
module.exports.client=client;module.exports.providerInput=providerInput;module.exports.fqdn=fqdn;
