'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const policy=require('../lib/security'),auth=require('../lib/auth');
test('production rejects shared-domain or unprefixed cookies and accepts a secure host-only cookie',()=>{
 const {spawnSync}=require('node:child_process');
 const check=(name,domain)=>spawnSync(process.execPath,['-e',`require(${JSON.stringify(path.resolve(__dirname,'../lib/config.js'))})`],{env:{...process.env,SSO_ENV_FILE:path.join(os.tmpdir(),'nonexistent-sso-env'),SSO_ISSUER:'https://sso.chitanda.net',SSO_COOKIE_NAME:name,SSO_COOKIE_DOMAIN:domain},windowsHide:true,stdio:'pipe'}).status;
 assert.equal(check('__Host-chitanda_sso_session',''),0);assert.notEqual(check('chitanda_sso_session',''),0);assert.notEqual(check('__Host-chitanda_sso_session','.chitanda.net'),0);
});
test('identity roles fail closed and exact callbacks reject query, prefix and scheme changes',()=>{
 for(const v of [undefined,null,{},'broken','"admin"'])assert.deepEqual(policy.roles(v),[]);
 assert.deepEqual(policy.roles('["admin"]'),['admin']);
 const callbacks=['https://datahub.chitanda.net/tunnel/sso/callback'];
 assert.equal(policy.exactRedirect(callbacks[0],callbacks),true);
 for(const value of [callbacks[0]+'?evil=1',callbacks[0]+'/more','http://datahub.chitanda.net/tunnel/sso/callback','https://evil.example/tunnel/sso/callback','javascript:alert(1)'])assert.equal(policy.exactRedirect(value,callbacks),false);
 assert.equal(policy.safeLogout('/\\evil.example','https://sso.chitanda.net',[]),'/login');
 assert.equal(policy.safeLogout('https://evil.example','https://sso.chitanda.net',[]),'/login');
});
test('JWT algorithms and expiry are mandatory, while valid signatures and expiry are accepted',()=>{
 const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const token=auth.signJwt({sub:'usr_fixture'},pair.privateKey,'test',60);assert.equal(auth.verifyJwt(token,pair.publicKey).sub,'usr_fixture');
 const sign=(header,body)=>{const h=Buffer.from(JSON.stringify(header)).toString('base64url'),p=Buffer.from(JSON.stringify(body)).toString('base64url');return h+'.'+p+'.'+crypto.sign('RSA-SHA256',Buffer.from(h+'.'+p),pair.privateKey).toString('base64url');};
 for(const token of [sign({alg:'RS256'},{sub:'usr_fixture'}),sign({alg:'none'},{exp:Date.now()/1000+60}),sign({alg:'HS256'},{exp:Date.now()/1000+60}),sign({alg:'RS256'},{exp:0}),sign({alg:'RS256',crit:['unsupported']},{exp:Date.now()/1000+60})])assert.throws(()=>auth.verifyJwt(token,pair.publicKey));
});
test('new stores require explicit initial credentials and issue random client secrets',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'sso-store-'));let store;
 try{
  process.env.SSO_DATA_DIR=directory;process.env.SSO_ISSUER='http://127.0.0.1:9787';process.env.SSO_COOKIE_NAME='chitanda_sso_session';process.env.SSO_ENV_FILE=path.join(directory,'missing');
  const config=require('../lib/config');config.adminUsername='fixture';config.adminPasswordHash=await auth.createPasswordHash('Fixture-2026!');
  const Store=require('../lib/store');store=new Store(directory);const c=store.getOAuthClient('data-platform');assert.match(c.client_secret,/^sec_[a-f0-9]{64}$/);assert.deepEqual(c.redirect_uris,['https://datahub.chitanda.net/tunnel/sso/callback']);
  const u=store.getUserByUsername('fixture'),session=store.createSession(u.id,'fixture-cookie','127.0.0.1','test');assert.equal(store.activeSession(session.id,u.id),true);store.revokeSession(session.id);assert.equal(store.activeSession(session.id,u.id),false);
  assert.equal(store.activeSession('missing',u.id),false);
  const now=Date.now(),code='123456',secret=auth.generateTotpSecret();
  assert.equal(store.consumeTotp(u.id,secret,code,now),true);
  assert.equal(store.consumeTotp(u.id,secret,code,now+61000),false,'future-window OTP remains protected beyond 60 seconds');
  store.db.close();store=new Store(directory);
  assert.equal(store.consumeTotp(u.id,secret,code,now+89000),false,'OTP replay protection survives a restart');
  assert.equal(store.consumeTotp(u.id,secret,code,now+91000),true);
  assert.ok(!store.db.prepare('SELECT code_hash FROM totp_uses').get().code_hash.includes(code));
  const expired=store.createSession(u.id,'expired','127.0.0.1','test',-60000);
  assert.ok(!store.listSessionsForUser(u.id).some(s=>s.id===expired.id),'same-day expired sessions are not shown as active');
  let defense=require('../lib/defense');
  for(let i=0;i<8;i++)defense.recordLoginFailure('198.51.100.15','fixture');
  assert.equal(defense.checkLoginAllowed('198.51.100.15','fixture').allowed,false);
  delete require.cache[require.resolve('../lib/defense')];defense=require('../lib/defense');
  assert.equal(defense.checkLoginAllowed('198.51.100.15','fixture').allowed,false,'login lockout survives a service restart');
  assert.equal(defense.getClientIp({socket:{remoteAddress:'198.51.100.15'},headers:{'x-real-ip':'127.0.0.1'}}),'198.51.100.15','untrusted peers cannot spoof a forwarded source');
 }finally{store?.db.close();fs.rmSync(directory,{recursive:true,force:true});}
});
