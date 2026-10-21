'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs'),os=require('node:os'),crypto=require('node:crypto'),http=require('node:http'),{spawn}=require('node:child_process');
const auth=require('../lib/auth');
const password='SSO-regression-fixture-2026!';

// Hooks exist only in this isolated child process, never in the service source.
async function fixture(t){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'sso-regression-'));
 const hash=await auth.createPasswordHash(password);
 const code=`
 const {server,store}=require(${JSON.stringify(path.resolve(__dirname,'../server.js'))});
 const auth=require(${JSON.stringify(path.resolve(__dirname,'../lib/auth.js'))});
 let armed=false,release;const original=auth.verifyPasswordHash;
 auth.verifyPasswordHash=async(...args)=>{const result=await original(...args);if(armed){armed=false;await new Promise(r=>{release=r;process.send({held:true});});}return result;};
 const user=()=>store.getUserByUsername('fixture');
 process.on('message',msg=>{try{let result;const u=user();switch(msg.action){
 case 'session':{const token=require('node:crypto').randomBytes(32).toString('base64url');result={...store.createSession(u.id,token,'127.0.0.1','fixture'),userId:u.id};break;}
 case 'refresh':result=store.createRefreshToken('data-platform',u.id,'openid profile',msg.session);break;
 case 'client':result=store.getOAuthClient('data-platform').client_secret;break;
 case 'mfa':store.setTotpSecret(u.id,msg.secret);msg.enabled?store.enableTotp(u.id):store.disableTotp(u.id);result=true;break;
 case 'state':result={enabled:user().totp_enabled,secret:user().totp_secret};break;
 case 'revoke':store.revokeSession(msg.session);result=true;break;
 case 'arm':armed=true;result=true;break;
 case 'resume':release();release=null;result=true;break;
 default:throw Error('Unknown fixture hook');
 }process.send({id:msg.id,result});}catch(e){process.send({id:msg.id,error:e.message});}});
 server.listen(0,'127.0.0.1',()=>process.send({port:server.address().port}));`;
 const child=spawn(process.execPath,['-e',code],{windowsHide:true,stdio:['ignore','pipe','pipe','ipc'],env:{...process.env,SSO_ENV_FILE:path.join(directory,'missing'),SSO_DATA_DIR:directory,SSO_ISSUER:'http://127.0.0.1:9787',SSO_COOKIE_NAME:'fixture_session',SSO_COOKIE_DOMAIN:'',SSO_ACCESS_MODE:'',CHITANDA_ADMIN_USERNAME:'fixture',CHITANDA_ADMIN_PASSWORD_HASH:hash}});
 const pending=new Map();let nextId=0,held=false,heldResolve;let logs='';
 child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);
 child.on('message',msg=>{if(msg.held){held=true;heldResolve?.();}if(msg.id){const p=pending.get(msg.id);pending.delete(msg.id);msg.error?p.reject(Error(msg.error)):p.resolve(msg.result);}});
 t.after(async()=>{if(child.exitCode===null)await new Promise(resolve=>{child.once('exit',resolve);child.kill();});fs.rmSync(directory,{recursive:true,force:true});});
 const port=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Fixture startup timeout '+logs)),10000);child.on('message',msg=>{if(msg.port){clearTimeout(timer);resolve(msg.port);}});child.once('exit',()=>{clearTimeout(timer);reject(Error('Fixture exited '+logs));});});
 const origin='http://127.0.0.1:9787',base='http://127.0.0.1:'+port;
 const rpc=(action,args={})=>new Promise((resolve,reject)=>{const id=++nextId;pending.set(id,{resolve,reject});child.send({id,action,...args});});
 async function request(url,{method='GET',body,cookie}={}){
  const response=await fetch(base+url,{method,headers:{Connection:'close',Origin:origin,...(body===undefined?{}:{'Content-Type':'application/json'}),...(cookie?{Cookie:'fixture_session='+cookie.token}:{})},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'manual'});
  return {status:response.status,headers:response.headers,json:await response.json()};
 }
 return {rpc,request,base,origin,held:async()=>{if(held){held=false;return;}await new Promise(r=>{heldResolve=r;});held=false;heldResolve=null;}};
}

test('unauthenticated refresh replay cannot revoke a user; authenticated replay still revokes it',async t=>{
 const f=await fixture(t),s=await f.rpc('session'),secret=await f.rpc('client'),token=await f.rpc('refresh',{session:s.id});
 const refresh=(clientSecret=secret,clientId='data-platform')=>f.request('/oauth/token',{method:'POST',body:{grant_type:'refresh_token',refresh_token:token,client_id:clientId,client_secret:clientSecret}});
 assert.equal((await refresh()).status,200);
 assert.equal((await refresh('wrong')).status,401);
 assert.equal((await refresh(secret,'moegallery')).status,401);
 assert.equal((await f.request('/api/auth/me',{cookie:s})).status,200);
 assert.equal((await refresh()).status,400);
 assert.equal((await f.request('/api/auth/me',{cookie:s})).status,401);
});

test('MFA setup reauthenticates, revokes older sessions, and disable requires password plus unused OTP',async t=>{
 const f=await fixture(t),s=await f.rpc('session'),other=await f.rpc('session');
 const post=(p,body)=>f.request('/api/auth/totp/'+p,{method:'POST',cookie:s,body});
 assert.equal((await post('setup',{})).status,400);
 assert.equal((await post('setup',{password:'wrong'})).status,400);
 const setup=await post('setup',{password});assert.equal(setup.status,200);assert.match(setup.json.qrSvg,/<svg/);
 const code=auth.getTotpCode(setup.json.secret);
 assert.equal((await post('verify',{code})).status,200);
 assert.equal((await f.request('/api/auth/me',{cookie:other})).status,401);
 assert.equal((await post('verify',{code})).status,409);
 assert.equal((await post('disable',{password})).status,400);
 assert.equal((await post('disable',{password,code})).status,400,'the setup OTP cannot be replayed to disable MFA');
 const futureCode=auth.getTotpCode(setup.json.secret,30,Date.now()+30000);
 const newer=await f.rpc('session');
 assert.equal((await post('disable',{password,code:futureCode})).status,200);
 assert.equal((await f.request('/api/auth/me',{cookie:newer})).status,401);
 assert.equal((await f.rpc('state')).enabled,0);
});

test('MFA cannot be disabled after its session is revoked during password verification',async t=>{
 const f=await fixture(t),s=await f.rpc('session'),secret=auth.generateTotpSecret();
 await f.rpc('mfa',{secret,enabled:true});await f.rpc('arm');
 const result=f.request('/api/auth/totp/disable',{method:'POST',cookie:s,body:{password,code:auth.getTotpCode(secret)}});
 await f.held();await f.rpc('revoke',{session:s.id});await f.rpc('resume');
 assert.equal((await result).status,401);assert.equal((await f.rpc('state')).enabled,1);
});

test('login cannot use stale MFA state captured before password verification',async t=>{
 const f=await fixture(t);await f.rpc('arm');
 const result=f.request('/api/auth/login',{method:'POST',body:{username:'fixture',password}});
 await f.held();await f.rpc('mfa',{secret:auth.generateTotpSecret(),enabled:true});await f.rpc('resume');
 const r=await result;assert.equal(r.status,401);assert.equal(r.headers.get('set-cookie'),null);
});

test('MFA setup cannot overwrite a factor enabled concurrently by another session',async t=>{
 const f=await fixture(t),s=await f.rpc('session');await f.rpc('arm');
 const result=f.request('/api/auth/totp/setup',{method:'POST',cookie:s,body:{password}});
 await f.held();const secret=auth.generateTotpSecret();await f.rpc('mfa',{secret,enabled:true});await f.rpc('resume');
 assert.equal((await result).status,401);assert.deepEqual(await f.rpc('state'),{enabled:1,secret});
});

test('UTF-8 split between network chunks is preserved and oversized passwords are rejected',async t=>{
 const f=await fixture(t),s=await f.rpc('session'),body=Buffer.from(JSON.stringify({display_name:'千反田爱瑠',email:'fixture@example.test'}));
 const cut=body.indexOf(Buffer.from('千'))+1;
 const status=await new Promise((resolve,reject)=>{const req=http.request(f.base+'/api/auth/profile',{method:'POST',headers:{Origin:f.origin,Cookie:'fixture_session='+s.token,'Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write(body.subarray(0,cut));setTimeout(()=>req.end(body.subarray(cut)),20);});
 assert.equal(status,200);assert.equal((await f.request('/api/auth/me',{cookie:s})).json.user.displayName,'千反田爱瑠');
 assert.equal((await f.request('/api/auth/change-password',{method:'POST',cookie:s,body:{old_password:password,new_password:'a'.repeat(4097)}})).status,400);
});

test('login failure lockout blocks further guesses, including a correct password',async t=>{
 const f=await fixture(t);
 for(let i=0;i<8;i++)assert.equal((await f.request('/api/auth/login',{method:'POST',body:{username:'fixture',password:'wrong'}})).status,401);
 assert.equal((await f.request('/api/auth/login',{method:'POST',body:{username:'fixture',password}})).status,429);
});

test('an enabled but damaged MFA configuration fails closed',async t=>{
 const f=await fixture(t);await f.rpc('mfa',{secret:null,enabled:true});
 const result=await f.request('/api/auth/login',{method:'POST',body:{username:'fixture',password}});
 assert.equal(result.status,401);assert.equal(result.headers.get('set-cookie'),null);
});
