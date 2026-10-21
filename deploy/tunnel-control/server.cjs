'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net'),{execFileSync}=require('node:child_process');
const routePath=require('./route-path.cjs'),endpointCarriers=require('./endpoint-carriers.cjs');
const carrierNodes=()=>endpointCarriers.all(state);
const ensureCarrierCertificates=()=>endpointCarriers.certificates(state,ensureCertificate);
const VERSION=require('./package.json').version,sanitizeTLS=require('./telemetry.cjs'),certificates=require('./certificates.cjs');
const ROOT=__dirname,BASE='/tunnel',PORT=Number(process.env.CT_PORT||5092),DATA=process.env.CT_DATA||'/var/lib/chitanda-tunnel';
const DEFAULT_SNI='control.chitanda.net',ALLOWED_IPS=new Set((process.env.CT_ALLOWED_IPS||'123.119.187.76,127.0.0.1,::1').split(',').map(s=>s.trim()));
fs.mkdirSync(DATA,{recursive:true,mode:0o700});
const account=require('./account.cjs')(DATA);
const defense=require('./login-defense.cjs')(DATA);
const managementKeys=require('./management-keys.cjs')(DATA),managementAPI=require('./management-api.cjs');
const stateFile=path.join(DATA,'state.json'),secret=()=>crypto.randomBytes(32).toString('hex'),newId=p=>p+'-'+crypto.randomBytes(6).toString('hex');
let state=fs.existsSync(stateFile)?JSON.parse(fs.readFileSync(stateFile,'utf8')):{version:1,relays:[{id:'relay-hk',name:'香港优化机',host:'47.243.148.109',port:443,serverName:DEFAULT_SNI,path:'/api/v1/chitanda-bridge',psk:crypto.randomBytes(32).toString('base64'),token:secret()}],nodes:[{id:'mainland',name:'中国大陆',host:'110.42.32.161',role:'国内接入',token:secret()},{id:'international',name:'国际业务节点',host:'23.145.248.44',role:'国际接入',token:secret()}],routes:[],events:[]};
const reports=new Map(),history=new Map(),sessions=new Map();
const requestContext=new(require('node:async_hooks').AsyncLocalStorage)();
const systemSettings=require('./settings.cjs');state.settings=systemSettings.read(state.settings);
let deferSave=false;
const save=()=>{if(deferSave)return;fs.writeFileSync(stateFile+'.tmp',JSON.stringify(state,null,2),{mode:0o600});fs.renameSync(stateFile+'.tmp',stateFile);};
const audit=(action,detail)=>{const actor=requestContext.getStore()?.principal;state.events.unshift({id:crypto.randomUUID(),at:new Date().toISOString(),action,detail,...(actor?{actor:{type:'api-key',id:actor.id,name:actor.name}}:{})});state.events=state.events.slice(0,150);save();};
const equal=(a,b)=>{a=Buffer.from(String(a||''));b=Buffer.from(String(b||''));return a.length===b.length&&crypto.timingSafeEqual(a,b);};
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const json=(res,status,data,extra={})=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra});res.end(JSON.stringify(data));};
const body=async (req,limit=131072)=>{let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>limit)fail('请求体过大',413);chunks.push(chunk);}let value;try{value=JSON.parse(Buffer.concat(chunks).toString()||'{}');}catch{fail('JSON 格式不正确');}if(!value||typeof value!=='object'||Array.isArray(value))fail('请求数据应为 JSON 对象');if(req.managementPrincipal&&!managementKeys.active(req.managementPrincipal))fail('API 密钥已过期或已撤销',401);return value;};
const publicIP=require('./public-address.cjs');
const domain=v=>{v=String(v||DEFAULT_SNI).trim().toLowerCase();if(v.length>253||!v.includes('.')||!v.split('.').every(s=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)))fail('SNI 应为有效域名');return v;};
const pki=path.join(DATA,'pki');fs.mkdirSync(pki,{recursive:true,mode:0o700});
const openssl=args=>execFileSync(process.env.CT_OPENSSL||'openssl',args,{stdio:'pipe',timeout:15000,windowsHide:true});
if(!fs.existsSync(path.join(pki,'ca.crt'))){openssl(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','3650','-subj','/CN=Chitanda · 数据中台管理 Workspace CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',path.join(pki,'ca.key'),'-out',path.join(pki,'ca.crt')]);fs.chmodSync(path.join(pki,'ca.key'),0o600);}
state.ca=fs.readFileSync(path.join(pki,'ca.crt'),'utf8');
function ensureCertificate(relay){
 const routeNames=state.routes.filter(r=>routePath.relays(r).includes(relay.id)&&r.transport!=='stream').map(r=>domain(r.serverName));
 const names=[...new Set(routeNames.length?routeNames:[domain(relay.serverName)])].sort();
 const custom=state.certificates?.channel;if(custom?.mode==='custom'){const cert=new crypto.X509Certificate(custom.certPEM);for(const name of names)if(!cert.checkHost(name))fail('系统证书未覆盖 SNI：'+name);relay.certPEM=custom.certPEM;relay.keyPEM=custom.keyPEM;relay.certNames=names;relay.certExpires=cert.validTo;return;}
 if(names.length>24)fail('同一优化机最多配置 24 个 SNI 域名');
 if(relay.certPEM&&relay.keyPEM&&JSON.stringify(names)===JSON.stringify(relay.certNames)&&Date.parse(relay.certExpires)>Date.now()+7*86400000)return;
 const base=path.join(pki,relay.id);fs.writeFileSync(base+'.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+names.map(n=>'DNS:'+n).join(',')+'\n',{mode:0o600});
 openssl(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+names[0],'-keyout',base+'.key','-out',base+'.csr']);
 openssl(['x509','-req','-in',base+'.csr','-CA',path.join(pki,'ca.crt'),'-CAkey',path.join(pki,'ca.key'),'-set_serial','0x'+crypto.randomBytes(16).toString('hex'),'-days','365','-extfile',base+'.ext','-out',base+'.crt']);
 fs.chmodSync(base+'.key',0o600);relay.certPEM=fs.readFileSync(base+'.crt','utf8');relay.keyPEM=fs.readFileSync(base+'.key','utf8');relay.certNames=names;relay.certExpires=new crypto.X509Certificate(relay.certPEM).validTo;
}
if(!state.relays)state.relays=state.relay?[state.relay]:[];
for(const r of state.relays){if(r.serverName==='relay.internal'||!r.serverName)r.serverName=DEFAULT_SNI;r.port=r.port||443;}
for(const r of state.routes){r.relayId||=state.relays[0]?.id;r.transport||='h2';r.serverName=r.transport==='stream'?'':r.serverName&&r.serverName!=='relay.internal'?r.serverName:state.relays.find(n=>n.id===r.relayId)?.serverName||DEFAULT_SNI;r.tlsVerify=true;}
if(state.schema!==2){state.schema=2;state.version++;}delete state.relay;
const tunnelTokens=require('./tunnel-tokens.cjs'),httpAccess=require('./http-access.cjs');
const tunnelModel=require('./tunnels.cjs');tunnelModel.normalize(state);
ensureCarrierCertificates();save();
const report=id=>{const r=reports.get(id);return r?{...r,online:Date.now()-r.seen<50000}:{online:false};};
const certificateProfiles=require('./certificate-profiles.cjs')({dataDir:DATA,getState:()=>state,getReport:report,save,audit});
setInterval(()=>certificateProfiles.tick().catch(()=>console.error('Certificate maintenance failed')),5000).unref();
const certificateSummary=()=>({...certificates.read(state),profiles:certificateProfiles.read()});
const portManager=require('./ports.cjs')({getState:()=>state,getReport:report});
const routeChecks=require('./route-tests.cjs')({getState:()=>state,getReport:report,getSettings:()=>state.settings.routeChecks,storageFile:path.join(DATA,'route-checks.json')});
const domains=require('./domains.cjs')({dataDir:DATA,getState:()=>state,save,audit});
const installations=require('./node-installations.cjs')({dataDir:DATA,releaseDir:process.env.CT_RELEASE_DIR||path.join(ROOT,'releases'),getState:()=>state,getReport:report,enrollment,audit});
const dnsAddressSync=require('./dns-address-sync.cjs')({getState:()=>state,syncAddresses:domains.syncAddresses,isBusy:domains.isBusy,save,audit});
setInterval(()=>{dnsAddressSync.tick().catch(()=>console.error('DNS address maintenance failed'));},5000).unref();
const tunnelManager=tunnelModel({getState:()=>state,validateRoute,ensureCertificates:ensureCarrierCertificates,audit});
setInterval(()=>{try{routeChecks.tick();}catch{console.error('route check scheduling failed');}},5000).unref();
const linkKey=r=>[r.relayId,r.transport,r.serverName].join('|');
function cleanNode(n,relay=false){const role=relay?'优化机':n.role?.includes('国内')?'国内隧道':n.role?.includes('国际')?'国际隧道入口':n.role||'隧道入口',entryRoles=relay?[...new Set((state.origins||[]).filter(o=>o.endpoint===n.id).flatMap(o=>o.region==='mainland'||o.role?.includes('国内')?['国内隧道']:o.region==='international'||o.role?.includes('国际')?['国际隧道入口']:[]))]:[];return {id:n.id,name:n.name,host:n.host||'',role,entryRoles,kind:relay?'relay':'agent',certificateRoot:n.certificateRoot||'',installed:n.installation?.status==='installed',installation:n.installation||null,ingress:n.ingress||null,...(relay?{port:n.port,serverName:n.serverName,tlsVerify:true,certExpires:n.certExpires,certNames:n.certNames,protocols:report(n.id).capabilities?.transports||[]}:{}),...report(n.id)};}
function snapshot(){
 const relays=state.relays.map(n=>cleanNode(n,true)),nodes=state.nodes.map(n=>cleanNode(n));
 const routes=state.routes.map(r=>{const s=report(r.source),t=report(r.target),mids=routePath.relays(r).map(report),current=n=>Number(n.revision)>=state.version,linked=id=>{const peer=routePath.link(r,id);return !peer||report(id).links?.[[peer,r.transport,r.serverName].join('|')]?.connected;};return {...r,urlMode:!!httpAccess.route(state,r,r.source),listenError:s.listenerErrors?.[r.id]||null,test:routeChecks.get(r.id),configPending:[s,t,...mids].some(n=>n.online&&!current(n)),sourceOnline:!!(s.online&&current(s)&&s.listeners?.includes(r.id)&&linked(r.source)),targetOnline:!!(t.online&&current(t)&&linked(r.target)),relayOnline:!!(supportedRoute(r)&&mids.every(n=>n.online&&current(n))&&routePath.relays(r).every(linked))};});
 const origins=(state.origins||[]).map(n=>({...n,kind:'origin'}));const topology={nodes:[{id:'@controller',kind:'control',name:'数据中台',host:'',online:true},...origins,...relays,...nodes],edges:[...origins.flatMap(n=>[{id:'https:'+n.id,source:n.id,target:n.endpoint,kind:'https',name:'HTTPS 业务接入',transport:'https',enabled:true},{id:'https-return:'+n.id,source:n.endpoint,target:n.id,kind:'https',name:'HTTPS 业务接入',transport:'https',enabled:true}]),...[...relays,...nodes].map(n=>({id:'config:'+n.id,source:'@controller',target:n.id,kind:'control'})),...routes.flatMap(r=>{const p=routePath.path(r);return p.slice(1).map((target,i)=>({id:r.id+':hop:'+i,source:p[i],target,routeId:r.id,name:r.name,transport:r.transport,enabled:r.enabled,ready:r.sourceOnline&&r.targetOnline&&r.relayOnline}));})]};
 return {topology,origins,tunnels:tunnelModel.normalize(state),httpAccess:state.httpAccess||{},dns:domains.summary(),settings:{...systemSettings.read(state.settings),certificates:certificateSummary()},version:state.version,schema:2,now:new Date().toISOString(),defaultSNI:DEFAULT_SNI,relays,nodes,routes,events:state.events,histories:Object.fromEntries([...history].map(([id,s])=>[id,s.slice(-60)])),control:{version:VERSION,uptime:Math.floor(process.uptime()),memory:process.memoryUsage().rss}};
}
const brokerToken=(node,relay)=>crypto.createHmac('sha256',node.token).update('chitanda-broker-v1:'+relay.id).digest('hex');
const supportedRoute=r=>(!httpAccess.route(state,r,r.source)||[r.source,r.target].every(id=>[...state.nodes,...state.relays].find(n=>n.id===id)?.headerURLSupport===true))&&(!r.direct||routePath.path(r).every(id=>[...state.nodes,...state.relays].find(n=>n.id===id)?.directSupport===true))&&(routePath.relays(r).length===1||routePath.path(r).every(id=>[...state.nodes,...state.relays].find(n=>n.id===id)?.chainSupport===true));
function baseAgentConfig(id){
 const node=[...state.relays,...state.nodes].find(n=>n.id===id),routes=state.routes.filter(r=>(r.source===id||r.target===id||routePath.relays(r).includes(id))&&supportedRoute(r)).map(r=>({...r,...(httpAccess.route(state,r,id)?{httpAccess:httpAccess.route(state,r,id)}:{})}));
 const self=state.relays.find(r=>r.id===id)||carrierNodes().find(n=>n.id===id&&routes.some(r=>r.enabled&&routePath.relays(r).includes(id)));
 const peerIds=new Set(routes.map(r=>routePath.link(r,id)).filter(Boolean));
 const peers=carrierNodes().filter(r=>peerIds.has(r.id)&&r.host).map(r=>({id:r.id,host:r.host,port:r.port,streamPort:r.streamPort||11323,serverName:r.serverName,path:r.path,psk:r.psk,ca:state.ca,brokerToken:brokerToken(node,r)}));
 if(self){const allowed=new Set(routes.flatMap(r=>[routePath.previous(r,id),routePath.last(r)===id&&r.target!==id?r.target:null]).filter(Boolean));return {credentialVersion:'broker-v1',role:state.relays.some(n=>n.id===id)?'relay':'agent',revision:state.version,ca:state.ca,selfRelay:{id:self.id,host:self.host,port:self.port,streamPort:self.streamPort||11323,serverName:self.serverName,path:self.path,psk:self.psk,ca:state.ca,certPEM:self.certPEM,keyPEM:self.keyPEM},nodes:[...state.nodes,...state.relays].filter(n=>allowed.has(n.id)).map(n=>({id:n.id,token:brokerToken(n,self)})),relays:peers,routes};}
 return {credentialVersion:'broker-v1',role:'agent',revision:state.version,ca:state.ca,relays:peers,routes};
}
function agentConfig(id){const https=state.certificates?.https,node=[...state.nodes,...state.relays].find(n=>n.id===id);return {...baseAgentConfig(id),tunnelAccess:tunnelTokens.grants(state,id),httpsCertificate:certificateProfiles.forNode(id)||(https?.mode==='custom'&&https.nodeIds.includes(id)&&node.ingress&&new crypto.X509Certificate(https.certPEM).checkHost(node.ingress.domain)?{certPEM:https.certPEM,keyPEM:https.keyPEM}:null),checks:routeChecks.pending(id)};}
function validateRoute(input,id){
 if(input.enabled!==undefined&&typeof input.enabled!=='boolean')fail('enabled 必须为布尔值');
 const endpoints=[...state.nodes,...state.relays],source=endpoints.find(n=>n.id===input.source),target=endpoints.find(n=>n.id===input.target);
 if(!source||!target||source.id===target.id)fail('请选择不同的起点和终点');
 if(input.relayIds!==undefined&&(!Array.isArray(input.relayIds)||input.relayIds.length>8||input.relayIds.some(id=>typeof id!=='string')))fail('最多选择 8 台优化机');
 const requested=input.relayIds||[input.relayId||state.relays[0]?.id];
 const direct=requested.length===0||input.direct===true;
 const relayIds=direct?[requested[0]||[source,target].find(n=>state.relays.includes(n))?.id||target.id]:requested;
 if(new Set(relayIds).size!==relayIds.length)fail('优化机路径不可重复');
 if(direct&&(relayIds.length!==1||![source.id,target.id].includes(relayIds[0])))fail('直连只允许两端节点承接，不可插入第三台服务器');
 if(!direct&&relayIds.some(id=>!state.relays.some(n=>n.id===id)))fail('请选择已登记的优化机');
 if([source,target].some(n=>state.relays.includes(n)&&n.id!==(n===source?relayIds[0]:relayIds.at(-1))))fail('作为端点的优化机必须位于路径对应的首端或末端');
 if(relayIds.slice(1).includes(source.id)||relayIds.slice(0,-1).includes(target.id))fail('路径不可经过入口或服务端后再次绕行');
 const carrierNode=endpoints.find(n=>n.id===relayIds[0]);
 const listenPort=Number(input.listenPort),targetPort=Number(input.targetPort);if(!Number.isInteger(listenPort)||listenPort<1024||listenPort>65535||!Number.isInteger(targetPort)||targetPort<1||targetPort>65535)fail('监听端口应为 1024–65535，目标端口应为 1–65535');
 if(targetPort===5092)fail('控制台管理端口不可作为数据通道目标');
 if(input.enabled!==false)portManager.validate(source.id,listenPort,id);else if(state.routes.some(r=>r.id!==id&&r.source===source.id&&r.listenPort===listenPort))fail('入口端口已分配给其他通道',409);
 const name=String(input.name||'').trim(),transport=input.transport||'h2';if(!name||name.length>60)fail('线路名称应为 1–60 字符');if(!['h2','h3','stream'].includes(transport))fail('数据协议仅支持 H2、H3 或 Stream');if(input.tlsVerify===false)fail('TLS 证书验证必须启用');
 if(id&&state.domains?.some(b=>[b.mainlandRouteId,b.internationalRouteId].includes(id))&&state.routes.find(r=>r.id===id)?.source!==source.id)fail('已绑定域名的线路不能直接更换源节点',409);
 const serverName=transport==='stream'?'':domain(input.serverName||tunnelModel.defaultServerName(state,input,id)||carrierNodes().find(n=>n.id===relayIds[0])?.serverName||DEFAULT_SNI);
 if(direct&&!state.relays.includes(carrierNode))endpointCarriers.ensure(carrierNode,DEFAULT_SNI);
 const relay=carrierNodes().find(n=>n.id===relayIds[0]);
 return {id:id||crypto.randomUUID(),name,source:source.id,target:target.id,relayId:relay.id,...(input.relayIds?{relayIds:[...relayIds]}:{}),...(direct&&!state.relays.includes(carrierNode)?{direct:true}:{}),transport,serverName,tlsVerify:true,listenPort,targetPort,enabled:input.enabled!==false,createdAt:new Date().toISOString()};
}
async function writeTunnel(input,id){
 const before=structuredClone(state);let tunnel,binding;
 deferSave=true;
 try{
  tunnel=tunnelManager.write(input,id);
  if(input.businessDomain){
   const requested=require('./domains.cjs').fqdn(input.businessDomain);
   binding=(state.domains||[]).find(b=>b.tunnelId===tunnel.id&&b.domain===requested);
   if(!binding)binding=domains.create({tunnelId:tunnel.id,domain:requested,ttl:input.domainTTL??1});
  }
 }catch(e){state=before;throw e;}finally{deferSave=false;}
 save();
 if(binding&&input.publishDNS===true&&binding.status!=='published'){
  try{const p=await domains.preview(binding.id);await domains.publish(binding.id,p.fingerprint);return {ok:true,tunnel,binding,dns:{published:true}};}
  catch(e){binding.lastError=e.message;audit('域名发布待处理',binding.domain+' · '+e.message);return {ok:true,tunnel,binding,dns:{published:false,error:e.message}};}
 }
 return {ok:true,tunnel,binding};
}
function mutateRoute(input,id){const before=structuredClone(state);try{const candidate=validateRoute(input,id),old=state.routes,index=old.findIndex(r=>r.id===id);state.routes=index>=0?old.map((r,i)=>i===index?{...candidate,createdAt:r.createdAt}:r):[...old,candidate];ensureCarrierCertificates();return candidate;}catch(e){state=before;throw e;}}
function enrollment(n,relay){return {controller:process.env.CT_CONTROLLER_URL||'https://datahub.chitanda.net',controllerAddress:process.env.CT_CONTROLLER_ADDRESS||'',id:n.id,token:n.token,role:relay?'relay':'agent',ca:state.ca};}
const server=http.createServer((req,res)=>requestContext.run({},async()=>{try{
 for(const [k,v]of Object.entries({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"}))res.setHeader(k,v);
 let p=new URL(req.url,'http://localhost').pathname;const clientIP=String(req.headers['x-real-ip']||req.socket.remoteAddress||'').replace(/^::ffff:/,'');
 if(p.startsWith(BASE)&&!ALLOWED_IPS.has(clientIP))return json(res,403,{error:'访问被拒绝'});
 if(p===BASE+'/api/management-openapi'&&req.method==='GET'&&String(req.headers.accept||'').includes('text/html')&&new URL(req.url,'http://localhost').searchParams.get('format')!=='json'){
  res.writeHead(302,{'Location':BASE+'/api-docs','Cache-Control':'no-store'});return res.end();
 }
 if(p===BASE+'/api-docs'){
  const token=String(req.headers.cookie||'').match(/(?:^|;\s*)ct_session=([a-f0-9]{64})(?:;|$)/)?.[1],s=sessions.get(token);
  if(!s||s.until<Date.now()||s.clientIP!==clientIP){res.writeHead(302,{'Location':BASE+'/','Cache-Control':'no-store'});return res.end();}
 }
 if(p.startsWith(BASE+'/api/v1/')){
  const requested=p.slice((BASE+'/api/v1').length),route=managementAPI.match(requested,req.method),principal=managementKeys.authorize(req,route?.scope,clientIP);
  if(requested==='/openapi.json'&&req.method==='GET')return json(res,200,managementAPI.schema());
  if(!route)fail('API 路径或请求方法不存在',404);
  req.managementPrincipal=principal;res.setHeader('X-API-Version','1');
  if(route.action!=='panel')return json(res,200,managementAPI.view(route,snapshot()));
  requestContext.getStore().principal=principal;
  p=BASE+'/api'+route.panel;
 }
 if(p===BASE&&['GET','HEAD'].includes(req.method)){res.writeHead(302,{'Location':BASE+'/','Cache-Control':'no-store'});return res.end();}
 if(p.startsWith(BASE+'/api/')&&!['GET','HEAD'].includes(req.method)){
  const origin=req.headers.origin,host=String(req.headers.host||'');
  if(req.headers['sec-fetch-site']==='cross-site'||(origin&&![`https://${host}`,`http://${host}`].includes(origin)))return json(res,403,{error:'请求来源校验失败'});
  if(p===BASE+'/api/login'&&!String(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))return json(res,415,{error:'请使用 JSON 格式请求'});
 }
 if(p==='/health')return json(res,200,{ok:true});
 if((p==='/transit-node/install.sh'||p==='/install.sh')&&req.method==='GET'){res.writeHead(200,{'Content-Type':'text/x-shellscript; charset=utf-8','Cache-Control':'no-store'});return fs.createReadStream(path.join(ROOT,p==='/install.sh'?'node-bootstrap.sh':'node-install.sh')).pipe(res);}
 if(p==='/transit-node/enroll'&&req.method==='POST')return json(res,200,installations.claim(await body(req,4096),clientIP));
 if(p==='/transit-node/uninstalled'&&req.method==='POST'){
  const id=req.headers['x-node-id'],token=String(req.headers.authorization||'').replace(/^Bearer /,''),item=[...state.relays,...state.nodes].find(n=>n.id===id);
  if(!item||!equal(token,item.token))return json(res,401,{error:'节点认证失败'});
  const b=await body(req,512);if(!b||typeof b!=='object'||Object.keys(b).length)fail('卸载状态参数不正确');
  if(item.installation?.status!=='uninstalled'){item.installation={...item.installation,status:'uninstalled',uninstalledAt:new Date().toISOString()};reports.delete(id);audit('节点已卸载',item.name+' · 本机配置默认保留');}
  return json(res,200,{ok:true});
 }
 if(p==='/transit-node/release'||p==='/transit-node/status'||p.startsWith('/transit-node/releases/')){
  const id=req.headers['x-node-id'],token=String(req.headers.authorization||'').replace(/^Bearer /,''),item=[...state.relays,...state.nodes].find(n=>n.id===id);
  if(!item||!equal(token,item.token))return json(res,401,{error:'节点认证失败'});
  if(req.method!=='GET')return json(res,405,{error:'请求方式不支持'});
  if(p==='/transit-node/release')return json(res,200,installations.release());
  if(p==='/transit-node/status'){const r=report(id);return json(res,200,{id,online:!!r.online,version:r.version,revision:r.revision,seen:r.seen});}
  const platform=p.slice('/transit-node/releases/'.length);if(!/^linux-(amd64|arm64|armv7|386|riscv64|loong64|ppc64le|s390x)$/.test(platform))return json(res,404,{error:'安装包不存在'});
  const asset=installations.asset(platform);res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':asset.size,'Cache-Control':'no-store'});return fs.createReadStream(asset.file).pipe(res);
 }
 if(p==='/transit-node/sync'&&req.method==='POST'){
  const id=req.headers['x-node-id'],token=String(req.headers.authorization||'').replace(/^Bearer /,''),item=[...state.relays,...state.nodes].find(n=>n.id===id);
  if(!item||!equal(token,item.token))return json(res,401,{error:'节点认证失败'});
  const data=await body(req);if(!domains.isBusy()){
   if(data.ingress&&typeof data.ingress.domain==='string'&&net.isIP(data.ingress.domain)===0&&/^[a-z0-9.-]{1,253}$/.test(data.ingress.domain)&&data.ingress.domain.includes('.')){const ingress={domain:domain(data.ingress.domain),port:443};if(JSON.stringify(item.ingress)!==JSON.stringify(ingress)){item.ingress=ingress;save();}}
   if(publicIP(clientIP)&&item.host!==clientIP){item.host=clientIP;state.version++;audit('识别节点地址',item.name+' · '+clientIP);}
  }
  const r={seen:Date.now()},finite=n=>Number.isFinite(Number(n))&&Number(n)>=0?Math.min(Number(n),1e18):0;
  for(const k of ['uptime','memory','goroutines','rx','tx','active','connections','latency','revision'])if(k in data)r[k]=finite(data[k]);
  r.revision=Math.min(state.version,Math.floor(r.revision||0));r.version=String(data.version||'').slice(0,40);
  r.listeners=Array.isArray(data.listeners)?data.listeners.filter(id=>state.routes.some(v=>v.id===id&&v.source===item.id)).slice(0,128):[];
  r.ports={complete:data.ports?.complete===true&&Array.isArray(data.ports?.tcp)&&data.ports.tcp.length<=4096,tcp:Array.isArray(data.ports?.tcp)?[...new Set(data.ports.tcp.filter(p=>Number.isInteger(p)&&p>0&&p<=65535))].slice(0,4096):[],observedAt:new Date().toISOString()};
  r.listenerErrors={};for(const [routeId,value] of Object.entries(data.listenerErrors||{}).slice(0,128))if(state.routes.some(v=>v.id===routeId&&v.source===item.id)&&['port-in-use','listen-failed'].includes(value))r.listenerErrors[routeId]=value;
  r.links={};for(const route of state.routes.filter(v=>routePath.path(v).includes(id))){const peer=routePath.link(route,id);if(!peer)continue;const key=[peer,route.transport,route.serverName].join('|'),link=data.links?.[key];if(link&&typeof link==='object')r.links[key]={relayId:peer,transport:route.transport,connected:link.connected===true,latency:finite(link.latency),error:String(link.error||'').slice(0,240)};}
  if(data.capabilities&&typeof data.capabilities==='object')r.capabilities={transports:Array.isArray(data.capabilities.transports)?[...new Set(data.capabilities.transports.filter(v=>['h2','h3','stream'].includes(v)))]:[],tlsServer:data.capabilities.tlsServer===true,tlsClient:data.capabilities.tlsClient===true,routeProbe:data.capabilities.routeProbe===1?1:0,relayChain:data.capabilities.relayChain===1?1:0,headerURL:data.capabilities.headerURL===1?1:0,directEndpoint:data.capabilities.directEndpoint===1?1:0};
  if(r.capabilities&&item.headerURLSupport!==(r.capabilities.headerURL===1)){item.headerURLSupport=r.capabilities.headerURL===1;save();}
  if(r.capabilities&&item.chainSupport!==(r.capabilities.relayChain===1)){item.chainSupport=r.capabilities.relayChain===1;save();}
  if(r.capabilities&&item.directSupport!==(r.capabilities.directEndpoint===1)){item.directSupport=r.capabilities.directEndpoint===1;save();}
  r.tls=sanitizeTLS(data.tls,item,state);
  routeChecks.accept(id,data.routeChecks);
  reports.set(id,r);
  if(item.installation?.status!=='installed'){item.installation={status:'installed',installedAt:new Date().toISOString()};audit('节点已接入',item.name);}
  if(state.relays.some(n=>n.id===id)){const s=history.get(id)||[];s.push({at:Date.now(),rx:r.rx||0,tx:r.tx||0,uptime:r.uptime||0,active:r.active||0,memory:r.memory||0});if(s.length>120)s.shift();history.set(id,s);}
  return json(res,200,agentConfig(id));
 }
 if(p===BASE+'/api/login'&&req.method==='POST'){
  const ticket=defense.begin(clientIP);
  try{
   const b=await body(req);if(!account.profile().username)return json(res,503,{error:'管理员账号尚未配置'});
   if(!await account.login(b.username,b.password)){const retryAfter=defense.failure(ticket);return json(res,retryAfter?429:401,{error:retryAfter?`账号或密码不正确，请 ${retryAfter} 秒后重试`:'账号或密码不正确',...(retryAfter?{retryAfter}:{})},retryAfter?{'Retry-After':String(retryAfter)}:{});}
   defense.success(ticket);const token=secret(),csrf=secret();
   if(sessions.size>=32)sessions.delete(sessions.keys().next().value);
   sessions.set(token,{csrf,clientIP,until:Date.now()+43200000});return json(res,200,{ok:true,csrf},{'Set-Cookie':`ct_session=${token}; HttpOnly; SameSite=Strict; Path=/tunnel/; Max-Age=43200${process.env.CT_INSECURE==='1'?'':'; Secure'}`});
  }finally{defense.finish(ticket);}
 }
 if(p.startsWith(BASE+'/api/')){
  const token=String(req.headers.cookie||'').match(/(?:^|;\s*)ct_session=([a-f0-9]{64})(?:;|$)/)?.[1],s=sessions.get(token);if(!req.managementPrincipal&&(!s||s.until<Date.now()||s.clientIP!==clientIP))return json(res,401,{error:'请登录管理面板'});if(!req.managementPrincipal&&!['GET','HEAD'].includes(req.method)&&!equal(req.headers['x-csrf-token'],s.csrf))return json(res,403,{error:'请求校验失败，请刷新页面'});
  if(!['GET','HEAD'].includes(req.method)&&!String(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))return json(res,415,{error:'请使用 JSON 格式请求'});
  if(p===BASE+'/api/session'&&req.method==='GET')return json(res,200,{...account.profile(),csrf:s.csrf});
  if(p===BASE+'/api/logout'&&req.method==='POST'){sessions.delete(token);return json(res,200,{ok:true},{'Set-Cookie':'ct_session=; Path=/tunnel/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});}
  if(p===BASE+'/api/profile'&&req.method==='GET')return json(res,200,account.profile());
  if(p===BASE+'/api/avatar'&&req.method==='GET'){const image=account.avatar();if(!image)return json(res,404,{error:'尚未设置头像'});res.writeHead(200,{'Content-Type':'image/webp','Cache-Control':'no-store'});return res.end(image);}
  if(p===BASE+'/api/avatar'&&req.method==='PUT')return json(res,200,await account.setAvatar(await body(req,2900000),()=>sessions.get(token)===s&&s.until>Date.now()));
  if(p===BASE+'/api/security'&&req.method==='GET')return json(res,200,{...defense.snapshot(),allowedIPs:[...ALLOWED_IPS],sessionLimit:32});
  if(p===BASE+'/api/account'&&req.method==='PATCH'){
   const ticket=defense.begin(clientIP,'account');
   try{const result=await account.credentials(await body(req),()=>sessions.get(token)===s&&s.until>Date.now());defense.success(ticket);sessions.clear();audit('更新管理员账号','管理员账密已更新');return json(res,200,result,{'Set-Cookie':'ct_session=; Path=/tunnel/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});}
   catch(e){if(e.code==='BAD_CURRENT_PASSWORD')defense.failure(ticket);throw e;}finally{defense.finish(ticket);}
  }
  if(p===BASE+'/api/management-keys'&&req.method==='GET')return json(res,200,{...managementKeys.list(),allowedIPs:[...ALLOWED_IPS]});
  if(p===BASE+'/api/management-keys'&&req.method==='POST'){const result=managementKeys.create(await body(req));audit('创建管理 API 密钥',result.key.name+' · '+result.key.scopes.join(', '));return json(res,201,result);}
  const managementKeyMatch=p.match(/^\/tunnel\/api\/management-keys\/([a-f0-9]{16})$/);
  if(managementKeyMatch&&req.method==='DELETE'){if(Object.keys(await body(req)).length)fail('撤销密钥不接受额外参数');const k=managementKeys.revoke(managementKeyMatch[1]);audit('撤销管理 API 密钥',k.name);return json(res,200,{ok:true});}
  if(p===BASE+'/api/management-openapi'&&req.method==='GET')return json(res,200,managementAPI.schema());
  if(p===BASE+'/api/state'&&req.method==='GET')return json(res,200,snapshot());
  if(p===BASE+'/api/ports/available'&&req.method==='GET'){const u=new URL(req.url,'http://localhost');return json(res,200,portManager.available(u.searchParams.get('nodeId'),{routeId:u.searchParams.get('routeId')||undefined,preferred:Number(u.searchParams.get('preferred')||15081),avoid:u.searchParams.getAll('avoid').map(Number)}));}
  if(domains.isBusy()&&/\/api\/(tunnels|routes|nodes)(\/|$)/.test(p)&&!['GET','HEAD'].includes(req.method))fail('DNS 正在发布，请稍后修改隧道或节点',409);
  if(p===BASE+'/api/tunnels'&&req.method==='POST')return json(res,201,await writeTunnel(await body(req)));
  if(p===BASE+'/api/tunnels/merge'&&req.method==='POST')return json(res,200,{ok:true,tunnel:tunnelManager.merge(await body(req))});
  const httpMatch=p.match(/^\/tunnel\/api\/tunnels\/([a-zA-Z0-9-]+)\/http$/);
  if(httpMatch&&req.method==='PUT'){const t=tunnelManager.get(httpMatch[1]),result=httpAccess.update(state,t,await body(req));state.version++;audit('更新 URL 请求接入',t.name+' · '+(result.enabled?'已启用':'已停用'));return json(res,200,{ok:true,httpAccess:result,revision:state.version});}
  const tokenMatch=p.match(/^\/tunnel\/api\/tunnels\/([a-zA-Z0-9-]+)\/token(?:\/(reset))?$/);
  if(tokenMatch&&req.method==='POST'){if(Object.keys(await body(req)).length)fail('令牌请求不接受自定义参数');const t=tunnelManager.get(tokenMatch[1]);if(tokenMatch[2]){state.tunnelTokens[t.id]=secret();state.version++;audit('重置隧道令牌',t.name+' · 将自动下发入口节点');return json(res,200,{ok:true,revision:state.version});}return json(res,200,{tunnelId:t.id,token:state.tunnelTokens[t.id]});}
  const tunnelMatch=p.match(/^\/tunnel\/api\/tunnels\/([a-zA-Z0-9-]+)$/);
  if(tunnelMatch){const id=tunnelMatch[1];if(req.method==='PATCH')return json(res,200,await writeTunnel(await body(req),id));if(req.method==='DELETE'){await body(req);tunnelManager.remove(id);return json(res,200,{ok:true});}}
  if(p===BASE+'/api/dns-provider'&&req.method==='PUT')return json(res,200,await domains.configure(await body(req)));
  if(p===BASE+'/api/domains'&&req.method==='POST')return json(res,201,{binding:domains.create(await body(req))});
  const domainMatch=p.match(/^\/tunnel\/api\/domains\/([a-f0-9]{16})(?:\/(plan|publish))?$/);
  if(domainMatch){const [,id,action]=domainMatch;if(!action&&req.method==='PATCH')return json(res,200,{binding:domains.updateTTL(id,await body(req))});if(action==='plan'&&req.method==='POST'){if(Object.keys(await body(req)).length)fail('预览只使用已保存的绑定');return json(res,200,await domains.preview(id));}if(action==='publish'&&req.method==='POST')return json(res,200,await domains.publish(id,(await body(req)).fingerprint));if(!action&&req.method==='DELETE'){await body(req);domains.remove(id);return json(res,200,{ok:true});}}
  if(p===BASE+'/api/settings'&&req.method==='GET')return json(res,200,{...systemSettings.read(state.settings),certificates:certificateSummary()});
  if(p===BASE+'/api/certificate-orders'&&req.method==='GET')return json(res,200,{orders:await certificateProfiles.orders(new URL(req.url,'http://local').searchParams.get('rootDomain'))});
  if(p===BASE+'/api/certificate-profiles'&&req.method==='POST'){const profile=certificateProfiles.write(await body(req));return json(res,201,{ok:true,profile});}
  const certificateMatch=p.match(/^\/tunnel\/api\/certificate-profiles\/([a-f0-9]{16})(?:\/(sync))?$/);
  if(certificateMatch){const [,id,action]=certificateMatch;if(action==='sync'&&req.method==='POST'){if(Object.keys(await body(req)).length)fail('证书检查只使用已保存配置');certificateProfiles.start(id);return json(res,202,{ok:true});}if(!action&&req.method==='PUT')return json(res,200,{ok:true,profile:certificateProfiles.write(await body(req),id)});if(!action&&req.method==='DELETE'){await body(req);certificateProfiles.remove(id);return json(res,200,{ok:true});}}
  if(p===BASE+'/api/certificates'&&req.method==='PUT'){const b=await body(req);if(b.purpose==='https')fail('请先添加根域名，使用泛域名证书管理');if(!['channel','https'].includes(b.purpose)||!['auto','custom'].includes(b.mode))fail('证书设置不正确');const nodeIds=b.purpose==='https'?[...new Set(Array.isArray(b.nodeIds)?b.nodeIds:[])]:[];if(nodeIds.some(id=>![...state.nodes,...state.relays].some(n=>n.id===id&&n.ingress)))fail('请选择已有 HTTPS 入口的节点');if(b.mode==='custom'&&b.purpose==='https'&&!nodeIds.length)fail('请选择证书应用节点');const names=b.purpose==='channel'?carrierNodes().flatMap(n=>{const rs=state.routes.filter(r=>routePath.relays(r).includes(n.id)&&r.transport!=='stream');return rs.length?rs.map(r=>r.serverName):[n.serverName];}):nodeIds.map(id=>[...state.nodes,...state.relays].find(n=>n.id===id).ingress.domain);const next=b.mode==='custom'?{...certificates.validate(b,names,state.ca),nodeIds}:{mode:'auto'};const previousCertificates=state.certificates,previousRelays=state.relays,previousNodes=state.nodes;state.certificates={...state.certificates,[b.purpose]:next};if(b.purpose==='channel'){state.relays=structuredClone(previousRelays);state.nodes=structuredClone(previousNodes);try{for(const n of [...state.relays,...state.nodes.filter(n=>n.carrier).map(n=>n.carrier)]){delete n.certPEM;delete n.keyPEM;delete n.certNames;delete n.certExpires;}ensureCarrierCertificates();}catch(e){state.certificates=previousCertificates;state.relays=previousRelays;state.nodes=previousNodes;throw e;}}state.version++;audit('更新系统证书',(b.purpose==='channel'?'数据通道':'HTTPS 业务入口')+' · '+(b.mode==='auto'?'自动管理':'自定义证书'));return json(res,200,{ok:true,certificates:certificateSummary()});}
  if(p===BASE+'/api/settings'&&req.method==='PATCH'){const next=systemSettings.update(state.settings,await body(req));state.settings=next;audit('更新系统设置','自动测活'+(next.routeChecks.enabled?'已启用':'已暂停')+' · 间隔 '+next.routeChecks.intervalSeconds+' 秒 · 有效期 '+next.routeChecks.maxAgeSeconds+' 秒 · 节点自动更新'+(next.nodeUpdates.enabled?'已启用':'已暂停')+' · 检查间隔 '+next.nodeUpdates.intervalSeconds+' 秒');routeChecks.tick();return json(res,200,{ok:true,settings:{...systemSettings.read(state.settings),certificates:certificateSummary()}});}
  if(p===BASE+'/api/routes'&&req.method==='POST'){if(state.routes.length>=128)fail('最多配置 128 条数据通道');const r=mutateRoute(await body(req));tunnelModel.normalize(state);state.version++;audit('创建数据通道',r.name+' · '+r.transport.toUpperCase());return json(res,201,{ok:true,route:r});}
  const testMatch=p.match(/^\/tunnel\/api\/routes\/([a-zA-Z0-9-]+)\/test$/);
  if(testMatch&&req.method==='POST'){const route=state.routes.find(r=>r.id===testMatch[1]);if(!route)fail('数据通道不存在',404);if(Object.keys(await body(req)).length)fail('测试仅使用当前线路配置');return json(res,202,{ok:true,test:routeChecks.create(route)});}
  const routeMatch=p.match(/^\/tunnel\/api\/routes\/([a-zA-Z0-9-]+)$/);
  if(routeMatch){const i=state.routes.findIndex(r=>r.id===routeMatch[1]);if(i<0)fail('数据通道不存在',404);if(['PATCH','DELETE'].includes(req.method)&&state.tunnels?.some(t=>t.mode==='bidirectional'&&t.routeIds.includes(routeMatch[1])))fail('请在双向隧道中统一修改两个方向',409);if(req.method==='PATCH'){const r=mutateRoute({...state.routes[i],...await body(req)},state.routes[i].id);state.version++;audit('更新数据通道',r.name+' · '+r.transport.toUpperCase()+' · '+(r.enabled?'启用':'暂停'));return json(res,200,{ok:true});}if(req.method==='DELETE'){if(state.domains?.some(b=>[b.mainlandRouteId,b.internationalRouteId].includes(routeMatch[1])))fail('请先处理绑定此线路的业务域名',409);const [r]=state.routes.splice(i,1);state.version++;audit('删除数据通道',r.name);return json(res,200,{ok:true});}}
  if(p===BASE+'/api/nodes'&&req.method==='POST'){
   const b=await body(req);if(b.purpose!==undefined&&!['international','relay','mainland'].includes(b.purpose))fail('请选择国际隧道入口、优化机或国内隧道');const isRelay=b.purpose!==undefined?b.purpose==='relay':b.kind==='relay',mainland=b.purpose!==undefined?b.purpose==='mainland':b.region==='mainland';if(state.nodes.length+state.relays.length>=64)fail('最多登记 64 个节点');const name=String(b.name||'').trim();if(!name||name.length>60)fail('请填写 1–60 字符的节点名称');
   const n={id:newId(isRelay?'relay':'node'),name,host:'',role:isRelay?'优化机':mainland?'国内隧道':'国际隧道入口',token:secret()};
   if(isRelay){const port=Number(b.port||443);if(!Number.isInteger(port)||(port<1024&&port!==443)||port>65535)fail('中转端口应为 443 或 1024–65535');Object.assign(n,{port,serverName:domain(b.serverName),path:'/api/v1/chitanda-bridge',psk:crypto.randomBytes(32).toString('base64')});ensureCertificate(n);state.relays.push(n);}else state.nodes.push(n);
   state.version++;audit('添加节点',name+' · '+n.role);return json(res,201,{ok:true,node:cleanNode(n,isRelay)});
  }
  const nodeMatch=p.match(/^\/tunnel\/api\/nodes\/([a-zA-Z0-9-]+)$/);
  if(nodeMatch){const id=nodeMatch[1],relay=state.relays.find(n=>n.id===id),n=relay||state.nodes.find(n=>n.id===id);if(!n)fail('节点不存在',404);
   if(req.method==='DELETE'){
    const b=await body(req);if(Object.keys(b).some(k=>k!=='cascade')||b.cascade!==undefined&&typeof b.cascade!=='boolean')fail('cascade 必须为布尔值');
    const linked=state.routes.filter(r=>routePath.path(r).includes(id)),linkedIds=new Set(linked.map(r=>r.id)),affected=state.tunnels.filter(t=>t.routeIds.some(r=>linkedIds.has(r))),affectedIds=new Set(affected.map(t=>t.id));
    if(state.domains?.some(b=>affectedIds.has(b.tunnelId)||[b.mainlandRouteId,b.internationalRouteId].some(r=>linkedIds.has(r))))fail('请先处理绑定此节点的业务域名',409);
    if(linked.length&&!b.cascade)return json(res,409,{error:'节点被数据通道引用，请确认一并删除关联数据通道',routes:linked.map(r=>r.name)});
    if(linked.length&&req.managementPrincipal&&!req.managementPrincipal.scopes.includes('tunnels:write'))fail('级联删除还需要 tunnels:write 权限',403);
    const removedIds=new Set([...linkedIds,...affected.flatMap(t=>t.routeIds)]),deletedRoutes=state.routes.filter(r=>removedIds.has(r.id)).length;
    state.routes=state.routes.filter(r=>!removedIds.has(r.id));state.tunnels=state.tunnels.filter(t=>!affectedIds.has(t.id));tunnelModel.normalize(state);
    state.nodes=state.nodes.filter(x=>x.id!==id);state.relays=state.relays.filter(x=>x.id!==id);reports.delete(id);history.delete(id);state.version++;audit('删除节点',n.name+' · 撤销凭据并删除 '+deletedRoutes+' 条关联数据通道');return json(res,200,{ok:true,deletedRoutes});
   }
   if(req.method==='PATCH'){const b=await body(req),name=b.name===undefined?n.name:String(b.name).trim();if(!name||name.length>60)fail('节点名称应为 1–60 字符');if(b.certificateRoot!==undefined)certificateProfiles.assignNode(id,b.certificateRoot);n.name=name;state.version++;audit('更新节点',n.name);return json(res,200,{ok:true});}
  }
  if(p===BASE+'/api/installations'&&req.method==='POST'){const b=await body(req);if(Object.keys(b).some(k=>!['id','action'].includes(k))||typeof b.id!=='string')fail('安装命令参数不正确');return json(res,200,installations.issue(b.id,b.action));}
  if(p===BASE+'/api/enrollment'&&req.method==='POST'){const b=await body(req),relay=state.relays.find(n=>n.id===b.id),n=relay||state.nodes.find(n=>n.id===b.id);if(!n)fail('节点不存在',404);audit('获取接入配置',n.name);return json(res,200,enrollment(n,!!relay));}
  return json(res,404,{error:'接口不存在'});
 }
 if(req.method!=='GET'&&req.method!=='HEAD')return json(res,405,{error:'不支持该方法'});
 const file=({[BASE]:'index.html',[BASE+'/']:'index.html',[BASE+'/api-docs']:'api-docs.html',[BASE+'/api-docs.js']:'api-docs.js',[BASE+'/api-docs.css']:'api-docs.css',[BASE+'/app.js']:'app.js',[BASE+'/ui.js']:'ui.js',[BASE+'/onboarding.js']:'onboarding.js',[BASE+'/http-access.js']:'http-access.js',[BASE+'/graph-model.js']:'graph-model.js',[BASE+'/dashboard.js']:'dashboard.js',[BASE+'/style.css']:'style.css',[BASE+'/theme.css']:'theme.css',[BASE+'/account.js']:'account.js',[BASE+'/certificate-profiles.js']:'certificate-profiles.js',[BASE+'/settings.js']:'settings.js',[BASE+'/domains.js']:'domains.js',[BASE+'/security.js']:'security.js',[BASE+'/management-api.js']:'management-api.js',[BASE+'/favicon.ico']:'favicon.ico',[BASE+'/favicon.png']:'favicon.png',[BASE+'/brand-logo.webp']:'brand-logo.webp'})[p];if(!file)return json(res,404,{error:'页面不存在'});
 res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.ico':'image/x-icon','.png':'image/png','.webp':'image/webp'})[path.extname(file)]+(/\.(html|js|css)$/.test(file)?'; charset=utf-8':''),'Cache-Control':'no-store'});if(req.method==='HEAD')return res.end();if(path.extname(file)==='.html')return res.end(fs.readFileSync(path.join(ROOT,'public',file),'utf8').replaceAll('__BUILD_VERSION__',VERSION));fs.createReadStream(path.join(ROOT,'public',file)).pipe(res);
 }catch(e){console.error('request failed:',e.status?e.message:'internal error');if(!res.headersSent)json(res,e.status||500,{error:e.status?e.message:'服务暂时不可用',...(e.retryAfter?{retryAfter:e.retryAfter}:{})},e.retryAfter?{'Retry-After':String(e.retryAfter)}:{});else res.destroy();}}));
setInterval(()=>{for(const [k,v]of sessions)if(v.until<Date.now())sessions.delete(k);},600000).unref();
server.requestTimeout=15000;server.headersTimeout=10000;server.listen(PORT,'127.0.0.1',()=>console.log('Chitanda · 数据中台管理 v2 listening on 127.0.0.1:'+PORT));
module.exports={server};
