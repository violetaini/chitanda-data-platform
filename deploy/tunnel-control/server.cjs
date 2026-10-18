'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net'),{execFileSync}=require('node:child_process');
const VERSION=require('./package.json').version,sanitizeTLS=require('./telemetry.cjs');
const ROOT=__dirname,BASE='/tunnel',PORT=Number(process.env.CT_PORT||5092),DATA=process.env.CT_DATA||'/var/lib/chitanda-tunnel';
const DEFAULT_SNI='control.chitanda.net',ALLOWED_IPS=new Set((process.env.CT_ALLOWED_IPS||'123.119.187.76,127.0.0.1,::1').split(',').map(s=>s.trim()));
fs.mkdirSync(DATA,{recursive:true,mode:0o700});
const account=require('./account.cjs')(DATA);
const defense=require('./login-defense.cjs')(DATA);
const stateFile=path.join(DATA,'state.json'),secret=()=>crypto.randomBytes(32).toString('hex'),newId=p=>p+'-'+crypto.randomBytes(6).toString('hex');
let state=fs.existsSync(stateFile)?JSON.parse(fs.readFileSync(stateFile,'utf8')):{version:1,relays:[{id:'relay-hk',name:'香港优化节点',host:'47.243.148.109',port:443,serverName:DEFAULT_SNI,path:'/api/v1/chitanda-bridge',psk:crypto.randomBytes(32).toString('base64'),token:secret()}],nodes:[{id:'mainland',name:'中国大陆',host:'110.42.32.161',role:'国内接入',token:secret()},{id:'international',name:'国际业务节点',host:'23.145.248.44',role:'国际接入',token:secret()}],routes:[],events:[]};
const reports=new Map(),history=new Map(),sessions=new Map();
const systemSettings=require('./settings.cjs');state.settings=systemSettings.read(state.settings);
const save=()=>{fs.writeFileSync(stateFile+'.tmp',JSON.stringify(state,null,2),{mode:0o600});fs.renameSync(stateFile+'.tmp',stateFile);};
const audit=(action,detail)=>{state.events.unshift({id:crypto.randomUUID(),at:new Date().toISOString(),action,detail});state.events=state.events.slice(0,150);save();};
const equal=(a,b)=>{a=Buffer.from(String(a||''));b=Buffer.from(String(b||''));return a.length===b.length&&crypto.timingSafeEqual(a,b);};
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const json=(res,status,data,extra={})=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra});res.end(JSON.stringify(data));};
const body=async (req,limit=131072)=>{let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>limit)fail('请求体过大',413);chunks.push(chunk);}let value;try{value=JSON.parse(Buffer.concat(chunks).toString()||'{}');}catch{fail('JSON 格式不正确');}if(!value||typeof value!=='object'||Array.isArray(value))fail('请求数据应为 JSON 对象');return value;};
const publicIP=ip=>net.isIP(ip)&&!['127.0.0.1','::1'].includes(ip)&&!/^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\./.test(ip);
const domain=v=>{v=String(v||DEFAULT_SNI).trim().toLowerCase();if(v.length>253||!v.includes('.')||!v.split('.').every(s=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)))fail('SNI 应为有效域名');return v;};
const pki=path.join(DATA,'pki');fs.mkdirSync(pki,{recursive:true,mode:0o700});
const openssl=args=>execFileSync(process.env.CT_OPENSSL||'openssl',args,{stdio:'pipe',timeout:15000,windowsHide:true});
if(!fs.existsSync(path.join(pki,'ca.crt'))){openssl(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','3650','-subj','/CN=Chitanda · 数据中台管理 Workspace CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',path.join(pki,'ca.key'),'-out',path.join(pki,'ca.crt')]);fs.chmodSync(path.join(pki,'ca.key'),0o600);}
state.ca=fs.readFileSync(path.join(pki,'ca.crt'),'utf8');
function ensureCertificate(relay){
 const names=[...new Set([domain(relay.serverName),...state.routes.filter(r=>r.relayId===relay.id).map(r=>domain(r.serverName))])].sort();
 if(names.length>24)fail('同一优化机最多配置 24 个 SNI 域名');
 if(relay.certPEM&&relay.keyPEM&&JSON.stringify(names)===JSON.stringify(relay.certNames)&&Date.parse(relay.certExpires)>Date.now()+7*86400000)return;
 const base=path.join(pki,relay.id);fs.writeFileSync(base+'.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+names.map(n=>'DNS:'+n).join(',')+'\n',{mode:0o600});
 openssl(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+names[0],'-keyout',base+'.key','-out',base+'.csr']);
 openssl(['x509','-req','-in',base+'.csr','-CA',path.join(pki,'ca.crt'),'-CAkey',path.join(pki,'ca.key'),'-set_serial','0x'+crypto.randomBytes(16).toString('hex'),'-days','365','-extfile',base+'.ext','-out',base+'.crt']);
 fs.chmodSync(base+'.key',0o600);relay.certPEM=fs.readFileSync(base+'.crt','utf8');relay.keyPEM=fs.readFileSync(base+'.key','utf8');relay.certNames=names;relay.certExpires=new crypto.X509Certificate(relay.certPEM).validTo;
}
if(!state.relays)state.relays=state.relay?[state.relay]:[];
for(const r of state.relays){if(r.serverName==='relay.internal'||!r.serverName)r.serverName=DEFAULT_SNI;r.port=r.port||443;}
for(const r of state.routes){r.relayId||=state.relays[0]?.id;r.transport||='h2';r.serverName=r.serverName&&r.serverName!=='relay.internal'?r.serverName:state.relays.find(n=>n.id===r.relayId)?.serverName||DEFAULT_SNI;r.tlsVerify=true;}
if(state.schema!==2){state.schema=2;state.version++;}delete state.relay;
for(const r of state.relays)ensureCertificate(r);save();
const report=id=>{const r=reports.get(id);return r?{...r,online:Date.now()-r.seen<50000}:{online:false};};
const routeChecks=require('./route-tests.cjs')({getState:()=>state,getReport:report,getSettings:()=>state.settings.routeChecks,storageFile:path.join(DATA,'route-checks.json')});
setInterval(()=>{try{routeChecks.tick();}catch{console.error('route check scheduling failed');}},5000).unref();
const linkKey=r=>[r.relayId,r.transport,r.serverName].join('|');
function cleanNode(n,relay=false){return {id:n.id,name:n.name,host:n.host||'',role:relay?'优化节点':n.role,kind:relay?'relay':'agent',...(relay?{port:n.port,serverName:n.serverName,tlsVerify:true,certExpires:n.certExpires,certNames:n.certNames,protocols:report(n.id).capabilities?.transports||[]}:{}),...report(n.id)};}
function snapshot(){
 const relays=state.relays.map(n=>cleanNode(n,true)),nodes=state.nodes.map(n=>cleanNode(n));
 const routes=state.routes.map(r=>{const s=report(r.source),t=report(r.target),mid=report(r.relayId),key=linkKey(r),sl=s.links?.[key],tl=t.links?.[key],current=n=>Number(n.revision)>=state.version;return {...r,test:routeChecks.get(r.id),configPending:[s,t,mid].some(n=>n.online&&!current(n)),sourceOnline:!!(s.online&&current(s)&&s.listeners?.includes(r.id)&&(r.source===r.relayId||sl?.connected)),targetOnline:!!(t.online&&current(t)&&(r.target===r.relayId||tl?.connected)),relayOnline:!!(mid.online&&current(mid))};});
 const origins=(state.origins||[]).map(n=>({...n,kind:'origin'}));const topology={nodes:[{id:'@controller',kind:'control',name:'数据中台',host:'',online:true},...origins,...relays,...nodes],edges:[...origins.flatMap(n=>[{id:'https:'+n.id,source:n.id,target:n.endpoint,kind:'https',name:'HTTPS 业务接入',transport:'https',enabled:true},{id:'https-return:'+n.id,source:n.endpoint,target:n.id,kind:'https',name:'HTTPS 业务接入',transport:'https',enabled:true}]),...[...relays,...nodes].map(n=>({id:'config:'+n.id,source:'@controller',target:n.id,kind:'control'})),...routes.flatMap(r=>[{id:r.id+':source',source:r.source,target:r.relayId,routeId:r.id,name:r.name,transport:r.transport,enabled:r.enabled,ready:r.sourceOnline&&r.targetOnline&&r.relayOnline},{id:r.id+':target',source:r.relayId,target:r.target,routeId:r.id,name:r.name,transport:r.transport,enabled:r.enabled,ready:r.sourceOnline&&r.targetOnline&&r.relayOnline}])]};
 return {topology,origins,settings:systemSettings.read(state.settings),version:state.version,schema:2,now:new Date().toISOString(),defaultSNI:DEFAULT_SNI,relays,nodes,routes,events:state.events,histories:Object.fromEntries([...history].map(([id,s])=>[id,s.slice(-60)])),control:{version:VERSION,uptime:Math.floor(process.uptime()),memory:process.memoryUsage().rss}};
}
const brokerToken=(node,relay)=>crypto.createHmac('sha256',node.token).update('chitanda-broker-v1:'+relay.id).digest('hex');
function baseAgentConfig(id){
 const relay=state.relays.find(r=>r.id===id);
 if(relay){ensureCertificate(relay);return {credentialVersion:'broker-v1',role:'relay',revision:state.version,ca:state.ca,selfRelay:{id:relay.id,host:relay.host,port:relay.port,serverName:relay.serverName,path:relay.path,psk:relay.psk,ca:state.ca,certPEM:relay.certPEM,keyPEM:relay.keyPEM},nodes:[...state.nodes.filter(n=>state.routes.some(r=>r.relayId===id&&(r.source===n.id||r.target===n.id))).map(n=>({id:n.id,token:brokerToken(n,relay)})),...(state.routes.some(r=>r.relayId===id&&r.source===id)?[{id:relay.id,token:brokerToken(relay,relay)}]:[])],routes:state.routes.filter(r=>r.relayId===id)};}
 const node=state.nodes.find(n=>n.id===id),routes=state.routes.filter(r=>r.source===id||r.target===id),ids=new Set(routes.map(r=>r.relayId));
 return {credentialVersion:'broker-v1',role:'agent',revision:state.version,ca:state.ca,relays:state.relays.filter(r=>ids.has(r.id)&&r.host).map(r=>({id:r.id,host:r.host,port:r.port,serverName:r.serverName,path:r.path,psk:r.psk,ca:state.ca,brokerToken:brokerToken(node,r)})),routes};
}
function agentConfig(id){return {...baseAgentConfig(id),checks:routeChecks.pending(id)};}
function validateRoute(input,id){
 const endpoints=[...state.nodes,...state.relays],source=endpoints.find(n=>n.id===input.source),target=endpoints.find(n=>n.id===input.target),relay=state.relays.find(n=>n.id===(input.relayId||state.relays[0]?.id));
 if(!source||!target||source.id===target.id)fail('请选择不同的源节点和目标节点');if(!relay)fail('请选择优化节点');if([source,target].some(n=>state.relays.includes(n)&&n.id!==relay.id))fail('作为端点的优化节点必须与所选优化节点一致');
 const listenPort=Number(input.listenPort),targetPort=Number(input.targetPort);if(!Number.isInteger(listenPort)||listenPort<1024||listenPort>65535||!Number.isInteger(targetPort)||targetPort<1||targetPort>65535)fail('监听端口应为 1024–65535，目标端口应为 1–65535');
 if(targetPort===5092)fail('控制台管理端口不可作为数据通道目标');
 if(state.routes.some(r=>r.id!==id&&r.source===source.id&&r.listenPort===listenPort))fail('源节点上的监听端口已被使用',409);
 const name=String(input.name||'').trim(),transport=input.transport||'h2';if(!name||name.length>60)fail('线路名称应为 1–60 字符');if(!['h2','h3'].includes(transport))fail('数据协议仅支持 H2 或 H3');if(input.tlsVerify===false)fail('TLS 证书验证必须启用');
 return {id:id||crypto.randomUUID(),name,source:source.id,target:target.id,relayId:relay.id,transport,serverName:domain(input.serverName||relay.serverName),tlsVerify:true,listenPort,targetPort,enabled:input.enabled!==false,createdAt:new Date().toISOString()};
}
function mutateRoute(input,id){const candidate=validateRoute(input,id),old=state.routes,index=old.findIndex(r=>r.id===id);state.routes=index>=0?old.map((r,i)=>i===index?{...candidate,createdAt:r.createdAt}:r):[...old,candidate];try{ensureCertificate(state.relays.find(r=>r.id===candidate.relayId));}catch(e){state.routes=old;throw e;}return candidate;}
function enrollment(n,relay){audit('获取接入配置',n.name);return {controller:process.env.CT_CONTROLLER_URL||'https://datahub.chitanda.net',controllerAddress:'110.42.32.161:443',id:n.id,token:n.token,role:relay?'relay':'agent',ca:state.ca};}
const server=http.createServer(async(req,res)=>{try{
 for(const [k,v]of Object.entries({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"}))res.setHeader(k,v);
 const p=new URL(req.url,'http://localhost').pathname,clientIP=String(req.headers['x-real-ip']||req.socket.remoteAddress||'').replace(/^::ffff:/,'');
 if(p.startsWith(BASE)&&!ALLOWED_IPS.has(clientIP))return json(res,403,{error:'访问被拒绝'});
 if(p===BASE&&['GET','HEAD'].includes(req.method)){res.writeHead(302,{'Location':BASE+'/','Cache-Control':'no-store'});return res.end();}
 if(p.startsWith(BASE+'/api/')&&!['GET','HEAD'].includes(req.method)){
  const origin=req.headers.origin,host=String(req.headers.host||'');
  if(req.headers['sec-fetch-site']==='cross-site'||(origin&&![`https://${host}`,`http://${host}`].includes(origin)))return json(res,403,{error:'请求来源校验失败'});
  if(p===BASE+'/api/login'&&!String(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))return json(res,415,{error:'请使用 JSON 格式请求'});
 }
 if(p==='/health')return json(res,200,{ok:true});
 if(p==='/transit-node/sync'&&req.method==='POST'){
  const id=req.headers['x-node-id'],token=String(req.headers.authorization||'').replace(/^Bearer /,''),item=[...state.relays,...state.nodes].find(n=>n.id===id);
  if(!item||!equal(token,item.token))return json(res,401,{error:'节点认证失败'});
  const data=await body(req);if(publicIP(clientIP)&&item.host!==clientIP){item.host=clientIP;state.version++;audit('识别节点地址',item.name+' · '+clientIP);}
  const r={seen:Date.now()},finite=n=>Number.isFinite(Number(n))&&Number(n)>=0?Math.min(Number(n),1e18):0;
  for(const k of ['uptime','memory','goroutines','rx','tx','active','connections','latency','revision'])if(k in data)r[k]=finite(data[k]);
  r.revision=Math.min(state.version,Math.floor(r.revision||0));r.version=String(data.version||'').slice(0,40);
  r.listeners=Array.isArray(data.listeners)?data.listeners.filter(id=>state.routes.some(v=>v.id===id&&v.source===item.id)).slice(0,128):[];
  r.links={};for(const route of state.routes.filter(v=>v.source===id||v.target===id)){const key=linkKey(route),link=data.links?.[key];if(link&&typeof link==='object')r.links[key]={relayId:route.relayId,transport:route.transport,connected:link.connected===true,latency:finite(link.latency),error:String(link.error||'').slice(0,240)};}
  if(data.capabilities&&typeof data.capabilities==='object')r.capabilities={transports:Array.isArray(data.capabilities.transports)?[...new Set(data.capabilities.transports.filter(v=>['h2','h3'].includes(v)))]:[],tlsServer:data.capabilities.tlsServer===true,tlsClient:data.capabilities.tlsClient===true,routeProbe:data.capabilities.routeProbe===1?1:0};
  r.tls=sanitizeTLS(data.tls,item,state);
  routeChecks.accept(id,data.routeChecks);
  reports.set(id,r);
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
  const token=String(req.headers.cookie||'').match(/(?:^|;\s*)ct_session=([a-f0-9]{64})(?:;|$)/)?.[1],s=sessions.get(token);if(!s||s.until<Date.now()||s.clientIP!==clientIP)return json(res,401,{error:'请登录管理面板'});if(!['GET','HEAD'].includes(req.method)&&!equal(req.headers['x-csrf-token'],s.csrf))return json(res,403,{error:'请求校验失败，请刷新页面'});
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
  if(p===BASE+'/api/state'&&req.method==='GET')return json(res,200,snapshot());
  if(p===BASE+'/api/settings'&&req.method==='GET')return json(res,200,systemSettings.read(state.settings));
  if(p===BASE+'/api/settings'&&req.method==='PATCH'){const next=systemSettings.update(state.settings,await body(req));state.settings=next;audit('更新系统设置','自动测活'+(next.routeChecks.enabled?'已启用':'已暂停')+' · 间隔 '+next.routeChecks.intervalSeconds+' 秒 · 有效期 '+next.routeChecks.maxAgeSeconds+' 秒');routeChecks.tick();return json(res,200,{ok:true,settings:systemSettings.read(state.settings)});}
  if(p===BASE+'/api/routes'&&req.method==='POST'){if(state.routes.length>=128)fail('最多配置 128 条数据通道');const r=mutateRoute(await body(req));state.version++;audit('创建数据通道',r.name+' · '+r.transport.toUpperCase());return json(res,201,{ok:true,route:r});}
  const testMatch=p.match(/^\/tunnel\/api\/routes\/([a-zA-Z0-9-]+)\/test$/);
  if(testMatch&&req.method==='POST'){const route=state.routes.find(r=>r.id===testMatch[1]);if(!route)fail('数据通道不存在',404);if(Object.keys(await body(req)).length)fail('测试仅使用当前线路配置');return json(res,202,{ok:true,test:routeChecks.create(route)});}
  const routeMatch=p.match(/^\/tunnel\/api\/routes\/([a-zA-Z0-9-]+)$/);
  if(routeMatch){const i=state.routes.findIndex(r=>r.id===routeMatch[1]);if(i<0)fail('数据通道不存在',404);if(req.method==='PATCH'){const r=mutateRoute({...state.routes[i],...await body(req)},state.routes[i].id);state.version++;audit('更新数据通道',r.name+' · '+r.transport.toUpperCase()+' · '+(r.enabled?'启用':'暂停'));return json(res,200,{ok:true});}if(req.method==='DELETE'){const [r]=state.routes.splice(i,1);state.version++;audit('删除数据通道',r.name);return json(res,200,{ok:true});}}
  if(p===BASE+'/api/nodes'&&req.method==='POST'){
   const b=await body(req),isRelay=b.kind==='relay';if(state.nodes.length+state.relays.length>=64)fail('最多登记 64 个节点');const name=String(b.name||'').trim();if(!name||name.length>60)fail('请填写 1–60 字符的节点名称');
   const n={id:newId(isRelay?'relay':'node'),name,host:'',role:b.region==='mainland'?'国内接入':'国际接入',token:secret()};
   if(isRelay){const port=Number(b.port||443);if(!Number.isInteger(port)||(port<1024&&port!==443)||port>65535)fail('中转端口应为 443 或 1024–65535');Object.assign(n,{port,serverName:domain(b.serverName),path:'/api/v1/chitanda-bridge',psk:crypto.randomBytes(32).toString('base64')});ensureCertificate(n);state.relays.push(n);}else state.nodes.push(n);
   state.version++;audit('添加节点',name+' · '+(isRelay?'优化节点':'业务接入'));return json(res,201,{ok:true,node:cleanNode(n,isRelay)});
  }
  const nodeMatch=p.match(/^\/tunnel\/api\/nodes\/([a-zA-Z0-9-]+)$/);
  if(nodeMatch){const id=nodeMatch[1],relay=state.relays.find(n=>n.id===id),n=relay||state.nodes.find(n=>n.id===id);if(!n)fail('节点不存在',404);
   if(req.method==='DELETE'){const linked=state.routes.filter(r=>r.source===id||r.target===id||r.relayId===id),b=await body(req);if(linked.length&&!b.cascade)return json(res,409,{error:'节点被数据通道引用，请确认一并删除关联数据通道',routes:linked.map(r=>r.name)});state.routes=state.routes.filter(r=>!linked.includes(r));state.nodes=state.nodes.filter(x=>x.id!==id);state.relays=state.relays.filter(x=>x.id!==id);reports.delete(id);history.delete(id);state.version++;audit('删除节点',n.name+' · 撤销凭据并删除 '+linked.length+' 条关联数据通道');return json(res,200,{ok:true,deletedRoutes:linked.length});}
   if(req.method==='PATCH'){const b=await body(req);if(b.name!==undefined){const name=String(b.name).trim();if(!name||name.length>60)fail('节点名称应为 1–60 字符');n.name=name;}if(relay&&b.serverName!==undefined){const newName=domain(b.serverName),oldName=relay.serverName;relay.serverName=newName;for(const r of state.routes)if(r.relayId===id&&r.serverName===oldName)r.serverName=newName;ensureCertificate(relay);}state.version++;audit('更新节点',n.name);return json(res,200,{ok:true});}
  }
  if(p===BASE+'/api/enrollment'&&req.method==='POST'){const b=await body(req),relay=state.relays.find(n=>n.id===b.id),n=relay||state.nodes.find(n=>n.id===b.id);if(!n)fail('节点不存在',404);return json(res,200,enrollment(n,!!relay));}
  return json(res,404,{error:'接口不存在'});
 }
 if(req.method!=='GET'&&req.method!=='HEAD')return json(res,405,{error:'不支持该方法'});
 const file=({[BASE]:'index.html',[BASE+'/']:'index.html',[BASE+'/app.js']:'app.js',[BASE+'/ui.js']:'ui.js',[BASE+'/graph-model.js']:'graph-model.js',[BASE+'/dashboard.js']:'dashboard.js',[BASE+'/style.css']:'style.css',[BASE+'/theme.css']:'theme.css',[BASE+'/account.js']:'account.js',[BASE+'/settings.js']:'settings.js',[BASE+'/security.js']:'security.js',[BASE+'/favicon.ico']:'favicon.ico',[BASE+'/favicon.png']:'favicon.png',[BASE+'/brand-logo.webp']:'brand-logo.webp'})[p];if(!file)return json(res,404,{error:'页面不存在'});
 res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.ico':'image/x-icon','.png':'image/png','.webp':'image/webp'})[path.extname(file)]+(/\.(html|js|css)$/.test(file)?'; charset=utf-8':''),'Cache-Control':'no-store'});if(req.method==='HEAD')return res.end();fs.createReadStream(path.join(ROOT,'public',file)).pipe(res);
 }catch(e){console.error('request failed:',e.status?e.message:'internal error');if(!res.headersSent)json(res,e.status||500,{error:e.status?e.message:'服务暂时不可用',...(e.retryAfter?{retryAfter:e.retryAfter}:{})},e.retryAfter?{'Retry-After':String(e.retryAfter)}:{});else res.destroy();}});
setInterval(()=>{for(const [k,v]of sessions)if(v.until<Date.now())sessions.delete(k);},600000).unref();
server.requestTimeout=15000;server.headersTimeout=10000;server.listen(PORT,'127.0.0.1',()=>console.log('Chitanda · 数据中台管理 v2 listening on 127.0.0.1:'+PORT));
module.exports={server};
