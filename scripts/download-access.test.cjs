'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),create=require('../deploy/tunnel-control/download-access.cjs');
test('download whitelist validates addresses, rejects injection, unknown fields and duplicates, and isolates node policies',()=>{
 const state={nodes:[{id:'a',name:'A'},{id:'b',name:'B'}],relays:[],events:[]},events=[];let report={online:true};const api=create({getState:()=>state,getReport:()=>report,audit:(...v)=>events.push(v)});
 assert.equal(api.forNode('a'),null);const s=api.create({name:'Downloads',domain:'downloads.example.com',nodeId:'a'});assert.equal(api.list()[0].status,'unsupported');assert.deepEqual(api.forNode('a').allowed,[]);
 for(const address of ['','1.2.3.4;allow all','1.2.3.4\ndeny all','127.1','2001:db8::1%eth0','1.2.3.4/33','2001:db8::/129','1.2.3.4/24/1'])assert.throws(()=>api.add(s.id,{address}));
 assert.throws(()=>api.add(s.id,{address:'1.2.3.4',backend:'http://169.254.169.254'}));assert.throws(()=>api.update(s.id,{enabled:'false'}));assert.throws(()=>api.create({name:'X',domain:'other.example.com',nodeId:'a'}),e=>e.status===409);
 api.add(s.id,{address:'203.0.113.8',note:'Origin'});assert.throws(()=>api.add(s.id,{address:'203.0.113.8/32'}),e=>e.status===409);api.add(s.id,{address:'2001:db8::/64'});assert.equal(api.forNode('b'),null);
 report={online:true,downloadAccess:{supported:true,ready:true,revision:1}};assert.equal(api.list()[0].status,'pending');report.downloadAccess.revision=3;assert.equal(api.list()[0].status,'applied');api.update(s.id,{enabled:false});report.downloadAccess.revision=4;assert.equal(api.list()[0].status,'paused');report.online=false;assert.equal(api.list()[0].status,'offline');
 const entry=api.list()[0].entries[0];api.remove(s.id,entry.id);assert.equal(api.forNode('a').allowed.length,1);api.drop(s.id,{});assert.equal(api.forNode('a'),null);assert.ok(events.length>=6);
});

test('download administration requires a browser session and CSRF; changes persist and are delivered only to the assigned node',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawn}=require('node:child_process'),{createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-download-access-')),base='http://127.0.0.1:5118',password='Fixture-Downloads-2026!';let child;const hash=await createAdminPasswordHash(password);
 const start=async()=>{child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),env:{...process.env,CT_PORT:'5118',CT_DATA:dir,CT_USERNAME:'fixture',CT_PASSWORD_HASH:hash,CT_INSECURE:'1',CT_AUTH_MODE:'local',CT_OPENSSL:process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl'},stdio:'ignore'});for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,60));}throw Error('Fixture startup failed');};
 const stop=async()=>{if(child){const c=child;child=null;await new Promise(resolve=>{c.once('exit',resolve);c.kill();});}};
 const request=async(p,method='GET',headers={},value)=>fetch(base+p,{method,headers:{'Content-Type':'application/json',...headers},...(value===undefined?{}:{body:JSON.stringify(value)})});
 const login=async()=>{const r=await request('/tunnel/api/login','POST',{}, {username:'fixture',password}),body=await r.json();return {Cookie:r.headers.get('set-cookie').split(';')[0],'X-CSRF-Token':body.csrf};};
 try{await start();assert.equal((await request('/tunnel/api/download-services')).status,401);const h=await login();assert.equal((await request('/tunnel/api/download-services','POST',{Cookie:h.Cookie},{name:'X',domain:'downloads.example.com',nodeId:'relay-hk'})).status,403);
 const r=await request('/tunnel/api/download-services','POST',h,{name:'Downloads',domain:'downloads.example.com',nodeId:'relay-hk'});assert.equal(r.status,201);const service=await r.json();assert.equal((await request('/tunnel/api/download-services/'+service.id+'/entries','POST',h,{address:'203.0.113.8',note:'origin'})).status,201);
 assert.equal((await request('/tunnel/api/nodes/relay-hk','DELETE',h,{cascade:true})).status,409);
 const enrollment=await (await request('/tunnel/api/enrollment','POST',h,{id:'relay-hk'})).json();const nodeHeaders={'X-Node-ID':enrollment.id,Authorization:'Bearer '+enrollment.token};
 const policy=await (await request('/transit-node/sync','POST',nodeHeaders,{revision:1,capabilities:{downloadAccess:1},downloadAccess:{supported:true,ready:true,revision:2}})).json();assert.deepEqual(policy.downloadAccess.allowed,['203.0.113.8']);
 await stop();await start();const h2=await login();const result=await (await request('/tunnel/api/download-services','GET',h2)).json();assert.equal(result.services[0].entries[0].address,'203.0.113.8');assert.equal(result.services[0].status,'offline');
 assert.equal((await request('/tunnel/api/download-services/'+service.id,'DELETE',h2,{})).status,200);assert.equal((await (await request('/transit-node/sync','POST',nodeHeaders,{})).json()).downloadAccess,null);
 }finally{await stop();fs.rmSync(dir,{recursive:true,force:true});}
});
