'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const keys=require('../deploy/tunnel-control/management-keys.cjs'),isPublic=require('../deploy/tunnel-control/public-address.cjs');
test('public-address validation rejects local, shared, metadata, multicast and mapped addresses',()=>{
 for(const ip of ['0.1.2.3','10.1.1.1','100.64.0.1','127.0.0.2','169.254.1.1','172.31.1.1','192.168.1.1','192.0.0.4','198.18.1.1','224.1.1.1','255.255.255.255','168.63.129.16','::1','::','fc00::1','fe80::1','ff02::1','::ffff:8.8.8.8','64:ff9b::808:808','2002:808:808::1',undefined,'invalid'])assert.equal(isPublic(ip),false,String(ip));
 for(const ip of ['8.8.8.8','110.42.98.254','47.243.148.109','168.138.209.1','2606:4700:4700::1111'])assert.equal(isPublic(ip),true,ip);
});
test('management keys are hashed, scoped, expiring, revocable across restarts and rate limited',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-api-keys-'));let now=1800000000000;
 try{let store=keys(dir,{now:()=>now});const issued=store.create({name:'monitor',scopes:['status:read'],expiresInDays:1}),req={method:'GET',headers:{authorization:'Bearer '+issued.secret}};
  assert.ok(!fs.readFileSync(path.join(dir,'management-keys.json'),'utf8').includes(issued.secret));assert.ok(!JSON.stringify(store.list()).includes(issued.secret));
  const principal=store.authorize(req,'status:read','127.0.0.1');assert.equal(store.active(principal),true);assert.throws(()=>store.authorize(req,'nodes:write','127.0.0.1'),e=>e.status===403);
  for(let i=0;i<118;i++)store.authorize(req,'status:read','127.0.0.1');assert.throws(()=>store.authorize(req,'status:read','127.0.0.1'),e=>e.status===429&&e.retryAfter>0);
  now+=60001;store=keys(dir,{now:()=>now});assert.ok(store.authorize(req,'status:read','127.0.0.1'));now+=86400000;assert.throws(()=>store.authorize(req,'status:read','127.0.0.1'),e=>e.status===401);
  const second=store.create({name:'second',scopes:['nodes:read'],expiresInDays:2});const secondReq={method:'GET',headers:{authorization:'Bearer '+second.secret}},secondPrincipal=store.authorize(secondReq,'nodes:read','127.0.0.1');store.revoke(second.key.id);assert.equal(store.active(secondPrincipal),false);assert.throws(()=>keys(dir,{now:()=>now}).authorize(secondReq,'nodes:read','127.0.0.1'),e=>e.status===401);
  assert.throws(()=>store.create({name:'wild',scopes:['*']}));assert.throws(()=>store.create({name:'long',scopes:['status:read'],expiresInDays:366}));assert.throws(()=>store.create({name:'extra',scopes:['status:read'],admin:true}));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('versioned API preserves browser security, limits scopes and uses the real node/tunnel workflows',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-api-http-')),base='http://127.0.0.1:5098',password='API-Fixture-2026!';let child;
 const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
 const start=async()=>{child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:'ignore',env:{...process.env,CT_PORT:'5098',CT_DATA:dir,CT_USERNAME:'api-admin',CT_PASSWORD_HASH:await createAdminPasswordHash(password),CT_INSECURE:'1',CT_OPENSSL:process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl'}});for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,80));}throw Error('fixture startup failed');};
 const stop=()=>new Promise(resolve=>{child.once('exit',resolve);child.kill();});
 const request=async(p,method='GET',headers={},value)=>{const r=await fetch(base+p,{method,headers:{Connection:'close',...headers},...(value===undefined?{}:{body:JSON.stringify(value)})}).catch(e=>{throw Error(method+' '+p+': '+e.message,{cause:e});});return {status:r.status,body:await r.json()};};
 try{await start();const login=await fetch(base+'/tunnel/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'api-admin',password})}),cookie=login.headers.get('set-cookie').split(';')[0],session=await login.json(),admin={Cookie:cookie,'X-CSRF-Token':session.csrf,'Content-Type':'application/json'};
  const create=async scopes=>{const r=await request('/tunnel/api/management-keys','POST',admin,{name:'fixture',scopes,expiresInDays:1});assert.equal(r.status,201);return {record:r.body,headers:{Authorization:'Bearer '+r.body.secret,'Content-Type':'application/json'}};};
  const docs=await fetch(base+'/tunnel/api-docs',{headers:{Cookie:cookie}});assert.equal(docs.status,200);assert.match(docs.headers.get('content-type'),/text\/html/);assert.match(await docs.text(),/api-docs\.js\?v=2\./);
  const noSession=await fetch(base+'/tunnel/api-docs',{redirect:'manual'});assert.equal(noSession.status,302);assert.equal(noSession.headers.get('location'),'/tunnel/');
  const browserLogin=await fetch(base+'/tunnel/api/management-openapi',{headers:{Accept:'text/html'}});assert.equal(browserLogin.url,base+'/tunnel/');assert.match(browserLogin.headers.get('content-type'),/text\/html/);
  assert.equal((await fetch(base+'/tunnel/api-docs',{headers:{Cookie:cookie,'X-Real-IP':'8.8.8.8'},redirect:'manual'})).status,403);
  const legacy=await fetch(base+'/tunnel/api/management-openapi',{headers:{Cookie:cookie,Accept:'text/html'},redirect:'manual'});assert.equal(legacy.status,302);assert.equal(legacy.headers.get('location'),'/tunnel/api-docs');
  const specRaw=await fetch(base+'/tunnel/api/management-openapi?format=json',{headers:{Cookie:cookie,Accept:'text/html'}});assert.equal((await specRaw.json()).openapi,'3.1.0');
  assert.equal((await request('/tunnel/api/management-openapi','GET',admin)).body.openapi,'3.1.0');
  assert.equal((await request('/tunnel/api/management-openapi')).status,401);
  const read=await create(['status:read','nodes:read','tunnels:read']),full=await create(['status:read','nodes:read','nodes:write','tunnels:read','tunnels:write','checks:write']),nodeOnly=await create(['nodes:write']);
  assert.equal((await request('/tunnel/api/v1/status')).status,401);assert.equal((await request('/tunnel/api/v1/status','GET',admin)).status,401);
  assert.equal((await request('/tunnel/api/management-keys','POST',{Cookie:cookie,'Content-Type':'application/json'},{name:'bad',scopes:['status:read']})).status,403);
  assert.equal((await request('/tunnel/api/v1/status','GET',{...read.headers,'X-Real-IP':'8.8.8.8'})).status,403);
  const status=await request('/tunnel/api/v1/status','GET',read.headers);assert.equal(status.status,200);assert.ok(status.body.nodes.total>=2);
  for(const p of ['account','enrollment','management-keys','dns-provider','certificate-profiles'])assert.equal((await request('/tunnel/api/v1/'+p,'POST',full.headers,{})).status,404);
  assert.equal((await request('/tunnel/api/account','PATCH',full.headers,{})).status,401);
  assert.equal((await request('/tunnel/api/v1/nodes','POST',read.headers,{name:'forbidden'})).status,403);
  assert.equal((await request('/tunnel/api/v1/nodes','POST',{...full.headers,Origin:'https://other.example'},{name:'forbidden'})).status,403);
  const cn=await request('/tunnel/api/v1/nodes','POST',full.headers,{name:'API CN',purpose:'mainland'}),intl=await request('/tunnel/api/v1/nodes','POST',full.headers,{name:'API Intl',purpose:'international'});assert.equal(cn.status,201);assert.equal(intl.status,201);
  const nodeId=cn.body.node.id;assert.equal((await request('/tunnel/api/v1/nodes/'+nodeId,'PATCH',full.headers,{name:'Renamed API node'})).status,200);
  assert.equal((await request('/tunnel/api/v1/nodes/'+nodeId,'GET',read.headers)).body.name,'Renamed API node');
  const created=await request('/tunnel/api/v1/tunnels','POST',full.headers,{name:'API pair',mode:'bidirectional',source:nodeId,target:intl.body.node.id,relayId:'relay-hk',listenPort:19181,targetPort:5081,reverseListenPort:19182,reverseTargetPort:5081});assert.equal(created.status,201);const t=created.body.tunnel;
  const list=await request('/tunnel/api/v1/tunnels','GET',read.headers);assert.equal(list.body.items.find(v=>v.id===t.id).routes.length,2);assert.ok(!/"(?:token|psk|keyPEM|certPEM|passwordHash)"/.test(JSON.stringify(list.body)));
  assert.equal((await request('/tunnel/api/v1/nodes/'+nodeId,'DELETE',full.headers,{cascade:'false'})).status,400);
  assert.equal((await request('/tunnel/api/v1/nodes/'+nodeId,'DELETE',nodeOnly.headers,{cascade:true})).status,403);
  assert.equal((await request('/tunnel/api/v1/tunnels/'+t.id,'PATCH',full.headers,{enabled:false})).status,200);const paused=(await request('/tunnel/api/v1/tunnels/'+t.id,'GET',read.headers)).body;assert.ok(paused.routes.every(r=>!r.enabled));
  assert.equal((await request('/tunnel/api/v1/routes/'+t.routeIds[0]+'/test','POST',read.headers,{})).status,403);
  assert.equal((await request('/tunnel/api/v1/routes/'+t.routeIds[0]+'/test','POST',full.headers,{})).status,409);
  assert.equal((await request('/tunnel/api/v1/routes/'+t.routeIds[0]+'/check','GET',read.headers)).status,200);
  assert.equal((await request('/tunnel/api/v1/tunnels/'+t.id,'PATCH',full.headers,{enabled:true})).status,200);
  const current=(await request('/tunnel/api/v1/status','GET',read.headers)).body.revision,wire=(await request('/tunnel/api/v1/tunnels/'+t.id,'GET',read.headers)).body.routes;
  const identities={};for(const id of [nodeId,intl.body.node.id,'relay-hk'])identities[id]=(await request('/tunnel/api/enrollment','POST',admin,{id})).body;
  const sync=async(id,extra={})=>request('/transit-node/sync','POST',{'Content-Type':'application/json','X-Node-ID':id,Authorization:'Bearer '+identities[id].token},{revision:current,capabilities:{routeProbe:1},listeners:wire.filter(r=>r.source===id).map(r=>r.id),links:{'relay-hk|h2|control.chitanda.net':{connected:true}},...extra});
  for(const id of Object.keys(identities))assert.equal((await sync(id)).status,200);
  assert.equal((await request('/tunnel/api/v1/routes/'+t.routeIds[0]+'/test','POST',full.headers,{})).status,202);const command=(await sync(nodeId)).body.checks[0];assert.ok(command);await sync(nodeId,{routeChecks:[{...command,status:'complete',attempts:3,samples:[5,6,7]}]});assert.equal((await request('/tunnel/api/v1/routes/'+t.routeIds[0]+'/check','GET',read.headers)).body.result.status,'success');
  const schema=await request('/tunnel/api/v1/openapi.json','GET',read.headers);assert.equal(schema.body.openapi,'3.1.0');assert.ok(schema.body.paths['/nodes/{id}'].delete);
  // The panel and API must both prune entire tunnel groups and their credentials.
  const before=JSON.parse(fs.readFileSync(path.join(dir,'state.json'),'utf8'));assert.ok(before.tunnelTokens[t.id]);
  assert.equal((await request('/tunnel/api/v1/nodes/'+nodeId,'DELETE',full.headers,{cascade:true})).status,200);const after=JSON.parse(fs.readFileSync(path.join(dir,'state.json'),'utf8'));assert.ok(!after.tunnels.some(v=>v.id===t.id));assert.ok(!after.tunnelTokens[t.id]);assert.ok(!after.routes.some(r=>t.routeIds.includes(r.id)));
  assert.equal((await request('/tunnel/api/management-keys/'+read.record.key.id,'DELETE',admin,{})).status,200);assert.equal((await request('/tunnel/api/v1/status','GET',read.headers)).status,401);
  // Revoking a key while its body is still arriving must stop the pending write.
  const slow=await create(['nodes:write']);let responseDone;
  const slowResult=new Promise((resolve,reject)=>{const req=require('node:http').request(base+'/tunnel/api/v1/nodes',{method:'POST',headers:slow.headers},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write('{"name":');responseDone=req;});
  await new Promise(r=>setTimeout(r,30));assert.equal((await request('/tunnel/api/management-keys/'+slow.record.key.id,'DELETE',admin,{})).status,200);responseDone.end('"must-not-create"}');assert.equal(await slowResult,401);
  assert.ok(!(await request('/tunnel/api/v1/nodes','GET',full.headers)).body.items.some(n=>n.name==='must-not-create'));
  const raw=fs.readFileSync(path.join(dir,'management-keys.json'),'utf8');assert.ok(!raw.includes(full.record.secret));assert.ok(!JSON.stringify((await request('/tunnel/api/state','GET',admin)).body).includes(full.record.secret));
  await stop();await start();assert.equal((await request('/tunnel/api/v1/status','GET',full.headers)).status,200);assert.equal((await request('/tunnel/api/v1/status','GET',read.headers)).status,401);
 }finally{if(child&&child.exitCode===null)await stop();fs.rmSync(dir,{recursive:true,force:true});}
});
