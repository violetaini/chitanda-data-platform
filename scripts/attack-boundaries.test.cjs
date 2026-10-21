'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),{spawn}=require('node:child_process'),{EventEmitter}=require('node:events');
const createGuard=require('../deploy/tunnel-control/request-guard.cjs');
test('request admission bounds rates, source cardinality and concurrency, releasing aborted responses once',()=>{
 let now=1000;const guard=createGuard({now:()=>now,maxBuckets:2,maxActive:2});
 const a=new EventEmitter(),b=new EventEmitter();guard.begin({},a,'first',{limit:3,concurrent:1});assert.throws(()=>guard.begin({},new EventEmitter(),'first',{limit:3,concurrent:1}),e=>e.status===429);guard.begin({},b,'second');assert.throws(()=>guard.take('third',1),e=>e.status===429);
 a.emit('close');a.emit('finish');guard.begin({},new EventEmitter(),'first',{limit:3,concurrent:1});assert.throws(()=>guard.take('first',3),e=>e.status===429&&e.retryAfter===60);
 now+=60001;b.emit('finish');guard.take('third',1);assert.throws(()=>guard.take('third',1),e=>e.status===429);
 const global=createGuard({maxActive:1});const c=new EventEmitter();global.begin({},c,'a');assert.throws(()=>global.begin({},new EventEmitter(),'b'),e=>e.status===429);c.emit('finish');global.begin({},new EventEmitter(),'b');
});
test('logout and node deletion revoke requests still receiving bodies; failed node auth and browser writes are bounded',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-attack-')),base='http://127.0.0.1:5099',password='Attack-Fixture-2026!';let child;
 const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
 const request=async(p,method='GET',headers={},body)=>{const r=await fetch(base+p,{method,headers:{Connection:'close',...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:r.status,body:await r.json(),headers:r.headers};};
 const login=async()=>{const r=await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},{username:'audit-admin',password});assert.equal(r.status,200);return {Cookie:r.headers.get('set-cookie').split(';')[0],'X-CSRF-Token':r.body.csrf,'Content-Type':'application/json'};};
 function partial(p,headers,start,declared){let req;const result=new Promise((resolve,reject)=>{req=http.request(base+p,{method:'POST',headers:{...headers,Connection:'close',...(declared?{'Content-Length':declared}:{})}},r=>{r.resume();r.once('end',()=>resolve(r.statusCode));});req.on('error',reject);req.write(start);});return {req,result};}
 try{
  child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:'ignore',env:{...process.env,CT_PORT:'5099',CT_DATA:dir,CT_USERNAME:'audit-admin',CT_PASSWORD_HASH:await createAdminPasswordHash(password),CT_INSECURE:'1',CT_OPENSSL:process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl'}});
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,80));}
  let admin=await login();assert.equal((await request('/tunnel/api/login','POST',{'Content-Type':'application/jsonp'},{})).status,415);
  assert.equal((await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},{username:'audit-admin',password:{toString:'invalid'}})).status,401,'malformed password data counts as a failed login instead of throwing');
  const big=partial('/tunnel/api/login',{'Content-Type':'application/json'},'{',32769);assert.equal(await big.result,413);big.req.destroy();
  const slow=partial('/tunnel/api/nodes',admin,'{"name":');await new Promise(r=>setTimeout(r,40));assert.equal((await request('/tunnel/api/logout','POST',admin,{})).status,200);slow.req.end('"after-logout","purpose":"international"}');assert.equal(await slow.result,401);assert.ok(!fs.readFileSync(path.join(dir,'state.json'),'utf8').includes('after-logout'));
  admin=await login();const created=await request('/tunnel/api/nodes','POST',admin,{name:'Delete during upload',purpose:'international'});assert.equal(created.status,201);const id=created.body.node.id,identity=(await request('/tunnel/api/enrollment','POST',admin,{id})).body,nodeHeaders={'Content-Type':'application/json','X-Node-ID':id,Authorization:'Bearer '+identity.token};
  const pending=partial('/transit-node/uninstalled',nodeHeaders,'{');await new Promise(r=>setTimeout(r,40));assert.equal((await request('/tunnel/api/nodes/'+id,'DELETE',admin,{})).status,200);pending.req.end('}');assert.equal(await pending.result,401);
  for(let i=0;i<30;i++)assert.equal((await request('/transit-node/status','GET',{'X-Node-ID':'bad',Authorization:'Bearer bad'})).status,401);
  const limited=await request('/transit-node/status','GET',{'X-Node-ID':'bad',Authorization:'Bearer bad'});assert.equal(limited.status,429);assert.ok(Number(limited.headers.get('retry-after'))>0);
  const cn=(await request('/tunnel/api/enrollment','POST',admin,{id:'mainland'})).body;assert.equal((await request('/transit-node/status','GET',{'X-Node-ID':cn.id,Authorization:'Bearer '+cn.token})).status,200,'bad auth quota does not prevent valid credentials');
  for(let i=0;i<120;i++)await request('/transit-node/status','GET',{'X-Node-ID':cn.id,Authorization:'Bearer '+cn.token});assert.equal((await request('/transit-node/status','GET',{'X-Node-ID':cn.id,Authorization:'Bearer '+cn.token})).status,429);
  for(let i=0;i<65;i++)await request('/tunnel/api/settings','PATCH',admin,{disallowed:true});assert.equal((await request('/tunnel/api/settings','PATCH',admin,{disallowed:true})).status,429);assert.equal((await request('/tunnel/api/state','GET',admin)).status,200,'mutation limit leaves reads available');
 }finally{if(child)await new Promise(resolve=>{child.once('exit',resolve);child.kill();});fs.rmSync(dir,{recursive:true,force:true});}
});
