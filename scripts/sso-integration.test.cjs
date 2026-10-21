'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto'),{spawn}=require('node:child_process');
const ssoSource=process.env.CT_SSO_SOURCE||path.resolve(__dirname,'../integrations/chitanda-sso');
test('real SSO and controller: PKCE, exact callbacks, subject authorization, CSRF, revocation and API isolation',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ct-sso-')),ssoDir=path.join(directory,'sso'),panelDir=path.join(directory,'panel');fs.mkdirSync(ssoDir);fs.mkdirSync(panelDir);
 const issuer='http://127.0.0.1:8797',origin='http://127.0.0.1:5097',secret='sec_'+crypto.randomBytes(32).toString('hex'),password='SSO-fixture-2026!';let sso,panel;let log='';
 const request=async(base,p,{method='GET',headers={},body}={})=>{const r=await fetch(base+p,{method,headers:{Connection:'close',...headers},redirect:'manual',...(body===undefined?{}:{body:typeof body==='string'?body:JSON.stringify(body)})});const raw=await r.text();let json;try{json=JSON.parse(raw);}catch{}return {status:r.status,headers:r.headers,json,raw};};
 const wait=async(base,p,child)=>{for(let i=0;i<100;i++){if(child.exitCode!==null)throw Error(log);try{if((await request(base,p)).status===200)return;}catch{}await new Promise(r=>setTimeout(r,80));}throw Error('Server did not start '+log);};
 const fork=(code,env)=>{const c=spawn(process.execPath,['-e',code],{windowsHide:true,stdio:['ignore','pipe','pipe'],env:{...process.env,...env}});c.stdout.on('data',b=>log+=b);c.stderr.on('data',b=>log+=b);return c;};
 try{
  const auth=require(path.join(ssoSource,'lib/auth.js')),hash=await auth.createPasswordHash(password);
  sso=fork(`const {server,store}=require(${JSON.stringify(path.join(ssoSource,'server.js'))});store.db.prepare("UPDATE users SET id='usr_fixture' WHERE username='fixture-admin'").run();store.db.prepare('UPDATE oauth_clients SET client_secret=?,redirect_uris=? WHERE client_id=?').run(${JSON.stringify(secret)},${JSON.stringify(JSON.stringify([origin+'/tunnel/sso/callback']))},'data-platform');server.listen(8797,'127.0.0.1');`,{SSO_DATA_DIR:ssoDir,SSO_ISSUER:issuer,SSO_COOKIE_NAME:'chitanda_sso_session',CHITANDA_ADMIN_USERNAME:'fixture-admin',CHITANDA_ADMIN_PASSWORD_HASH:hash,SSO_ENV_FILE:path.join(directory,'missing.env')});
  await wait(issuer,'/.well-known/openid-configuration',sso);
  const login=await request(issuer,'/api/auth/login',{method:'POST',headers:{Origin:issuer,'Content-Type':'application/json'},body:{username:'fixture-admin',password}});assert.equal(login.status,200);const ssoCookie=login.headers.getSetCookie()[0].split(';')[0];
  panel=fork(`require(${JSON.stringify(path.resolve(__dirname,'../deploy/tunnel-control/server.cjs'))})`,{CT_PORT:'5097',CT_DATA:panelDir,CT_AUTH_MODE:'sso',CT_SSO_ISSUER:issuer,CT_SSO_CLIENT_SECRET:secret,CT_SSO_ADMIN_SUBJECTS:'usr_fixture',CT_CONTROLLER_URL:origin,CT_INSECURE:'1',CT_OPENSSL:process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl'});
  await wait(origin,'/health',panel);
  assert.match((await request(origin,'/tunnel/')).raw,/<meta name="auth-mode" content="sso">/);
  assert.equal((await request(origin,'/tunnel/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:{username:'fixture-admin',password}})).status,410);
  assert.equal((await request(origin,'/tunnel/api/state',{headers:{Authorization:'Bearer fake','X-Authenticated-User-Id':'usr_fixture'}})).status,401);
  async function flow(){const start=await request(origin,'/tunnel/sso/start');assert.equal(start.status,302);const authUrl=new URL(start.headers.get('location'));assert.equal(authUrl.searchParams.get('code_challenge_method'),'S256');const browser=start.headers.getSetCookie()[0].split(';')[0];const granted=await request(issuer,authUrl.pathname+authUrl.search,{headers:{Cookie:ssoCookie}});assert.equal(granted.status,302);return {browser,url:new URL(granted.headers.get('location'))};}
  const f=await flow();assert.equal((await request(origin,f.url.pathname+f.url.search)).headers.get('location'),'/tunnel/?sso_error=1','callback requires originating browser cookie');
  const done=await request(origin,f.url.pathname+f.url.search,{headers:{Cookie:f.browser}});assert.equal(done.headers.get('location'),'/tunnel/');const panelCookie=done.headers.getSetCookie().find(v=>v.startsWith('ct_session=')).split(';')[0];
  assert.equal((await request(origin,f.url.pathname+f.url.search,{headers:{Cookie:f.browser}})).headers.get('location'),'/tunnel/?sso_error=1','flow is single use');
  const session=await request(origin,'/tunnel/api/session',{headers:{Cookie:panelCookie}});assert.equal(session.status,200);assert.equal(session.json.username,'fixture-admin');assert.equal(session.json.authMode,'sso');assert.ok(!session.raw.includes('accessToken'));
  const admin={Cookie:panelCookie,'X-CSRF-Token':session.json.csrf,'Content-Type':'application/json',Origin:origin};
  assert.equal((await request(origin,'/tunnel/api/settings',{method:'PATCH',headers:{Cookie:panelCookie,'Content-Type':'application/json'},body:{}})).status,403);
  assert.equal((await request(origin,'/tunnel/api/account',{method:'PATCH',headers:admin,body:{}})).status,410);
  assert.equal((await request(origin,'/tunnel/api/state',{headers:{Cookie:panelCookie,'X-Real-IP':'8.8.8.8'}})).status,403);
  assert.equal((await request(origin,'/tunnel/api/v1/status',{headers:{Cookie:panelCookie}})).status,401,'browser SSO does not become an API key');
  const authorize=new URL('/oauth/authorize',issuer);authorize.search=new URLSearchParams({client_id:'data-platform',redirect_uri:origin+'/tunnel/sso/callback',response_type:'code',nonce:'test-nonce',code_challenge:crypto.createHash('sha256').update('v'.repeat(43)).digest('base64url'),code_challenge_method:'S256'});
  let bad=new URL(authorize);bad.searchParams.set('redirect_uri',origin+'/tunnel/sso/callback?stolen=1');assert.equal((await request(issuer,bad.pathname+bad.search,{headers:{Cookie:ssoCookie}})).status,400);
  bad=new URL(authorize);bad.searchParams.set('code_challenge_method','plain');assert.equal((await request(issuer,bad.pathname+bad.search,{headers:{Cookie:ssoCookie}})).status,400);
  const grant=await request(issuer,authorize.pathname+authorize.search,{headers:{Cookie:ssoCookie}}),code=new URL(grant.headers.get('location')).searchParams.get('code');
  const exchange=(patch={})=>request(issuer,'/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'data-platform',client_secret:secret,code,redirect_uri:origin+'/tunnel/sso/callback',code_verifier:'v'.repeat(43),...patch}).toString()});
  assert.equal((await exchange({client_id:'moegallery'})).status,401,'code bound to authenticated client');assert.equal((await exchange({code_verifier:'z'.repeat(43)})).status,400);
  const tokens=await exchange();assert.equal(tokens.status,200,'failed authentication does not consume code');assert.equal((await exchange()).status,400);
  assert.equal((await request(issuer,'/oauth/userinfo',{headers:{Authorization:'Bearer '+tokens.json.access_token}})).status,200);
  assert.equal((await request(issuer,'/oauth/userinfo',{headers:{Authorization:'Bearer '+tokens.json.id_token}})).status,401);
  assert.equal((await request(issuer,'/api/clients',{headers:{Authorization:'Bearer '+tokens.json.access_token}})).status,401,'application token cannot administer SSO');
  assert.equal((await request(issuer,'/api/auth/profile',{method:'POST',headers:{Cookie:ssoCookie,'Content-Type':'application/json',Origin:'https://evil.example'},body:{}})).status,403);
  assert.equal((await request(issuer,'/api/auth/profile',{method:'POST',headers:{Cookie:ssoCookie,'Content-Type':'application/json'},body:{}})).status,403);
  assert.equal((await request(issuer,'/api/auth/totp/setup',{headers:{Cookie:ssoCookie}})).status,404,'GET cannot rotate MFA seed');
  const setup=await request(issuer,'/api/auth/totp/setup',{method:'POST',headers:{Cookie:ssoCookie,Origin:issuer,'Content-Type':'application/json'},body:{password}});assert.equal(setup.status,200);assert.match(setup.json.qrSvg,/<svg/);assert.ok(!setup.json.qrSvg.includes('qrserver.com'));
  for(const url of ['javascript:alert(1)','data:text/html,attack','https://user:secret@example.com'])assert.equal((await request(issuer,'/api/apps',{method:'POST',headers:{Cookie:ssoCookie,Origin:issuer,'Content-Type':'application/json'},body:{name:'invalid',url}})).status,400);
  const {chromium}=require('playwright'),browser=await chromium.launch({headless:true});
  try{
   const context=await browser.newContext();await context.addCookies([{name:'chitanda_sso_session',value:ssoCookie.split('=')[1],domain:'127.0.0.1',path:'/',httpOnly:true,sameSite:'Lax'}]);
   const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(origin+'/tunnel/');await page.locator('#shell').waitFor({state:'visible'});await page.locator('nav [data-view=account]').click();
   assert.equal(await page.locator('#account-form').count(),0,'SSO account page has no local password form');assert.equal(await page.getByRole('link',{name:'管理统一账号'}).count(),1);
   assert.equal(await page.locator('#settings-avatar').count(),1);assert.deepEqual(errors,[]);
   await page.screenshot({path:path.resolve(__dirname,'../tmp/sso-account-qa.png'),fullPage:true});
   await context.close();
  }finally{await browser.close();}
  const out=await request(issuer,'/oauth/logout',{headers:{Cookie:ssoCookie}});assert.match(out.headers.get('set-cookie'),/Max-Age=0/);
  assert.equal((await request(origin,'/tunnel/api/settings',{method:'PATCH',headers:admin,body:{}})).status,401,'SSO revocation is checked before writes');
  assert.equal((await request(origin,'/tunnel/api/session',{headers:{Cookie:panelCookie}})).status,401);
  assert.equal((await request(issuer,'/oauth/userinfo',{headers:{Authorization:'Bearer '+tokens.json.access_token}})).status,401,'revoked global session invalidates access token');
 }finally{for(const c of [panel,sso])if(c&&c.exitCode===null)await new Promise(resolve=>{c.once('exit',resolve);c.kill();});fs.rmSync(directory,{recursive:true,force:true});}
});
