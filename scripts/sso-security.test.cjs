'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const create=require('../deploy/tunnel-control/sso.cjs');
function fixture(){
 let time=1800000000000,nonce='',change={},active=true,unavailable=false,introspections=0,refreshes=0;
 const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),jwk={...publicKey.export({format:'jwk'}),kid:'fixture',alg:'RS256',use:'sig'};
 const token=()=>{const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'fixture'})).toString('base64url'),p=Buffer.from(JSON.stringify({iss:'https://sso.example',aud:'data-platform',sub:'usr_fixture',sid:'ses_fixture',token_use:'id',iat:time/1000,nbf:time/1000,exp:time/1000+900,nonce,...change})).toString('base64url');return h+'.'+p+'.'+crypto.sign('RSA-SHA256',Buffer.from(h+'.'+p),privateKey).toString('base64url');};
 const env={CT_AUTH_MODE:'sso',CT_CONTROLLER_URL:'https://datahub.example',CT_SSO_ISSUER:'https://sso.example',CT_SSO_CLIENT_SECRET:'sec_'+'a'.repeat(64),CT_SSO_ADMIN_SUBJECTS:'usr_fixture'};
 const adapter=create({env,now:()=>time,fetchImpl:async(url,options)=>{
  if(unavailable)throw Error('offline');let value;
  if(url.pathname==='/.well-known/jwks.json')value={keys:[jwk]};
  else if(url.pathname==='/oauth/token'){if(new URLSearchParams(options.body).get('grant_type')==='refresh_token')refreshes++;value={id_token:token(),access_token:'fixture-access',refresh_token:'rft_fixture'};}
  else if(url.pathname==='/oauth/introspect'){introspections++;value={active,sub:'usr_fixture',sid:'ses_fixture',client_id:'data-platform',exp:time/1000+900,roles:['admin'],username:'fixture',...change};}
  return new Response(JSON.stringify(value),{status:200});
 }});
 async function login(){const start=adapter.start({headers:{}},'ip'),u=new URL(start.location);nonce=u.searchParams.get('nonce');const url=new URL('https://datahub.example/tunnel/sso/callback');url.search=new URLSearchParams({code:'code_'+'x'.repeat(32),state:u.searchParams.get('state')});return (await adapter.complete({headers:{cookie:start.cookie.split(';')[0]}},url,'ip')).session;}
 return {adapter,login,env,set:(v)=>{change=v;},offline:()=>unavailable=true,revoke:()=>active=false,advance:ms=>time+=ms,stats:()=>({introspections,refreshes})};
}
test('JWT identity and administrator authorization fail closed; no username-based binding',async()=>{
 for(const claims of [{iss:'https://evil.example'},{aud:'different-client'},{sub:'usr_other'},{nonce:'wrong'},{sid:null},{exp:1},{roles:[]},{roles:'admin'},{roles:['operator']}]){const f=fixture();f.set(claims);await assert.rejects(f.login(),e=>e.status===401);}
 assert.throws(()=>create({env:{CT_AUTH_MODE:'mistyped'}}));assert.throws(()=>create({env:{CT_AUTH_MODE:'sso'}}));
 for(const address of ['example.com:9443','user:password@127.0.0.1:9443','127.0.0.1:9443/unsafe','127.0.0.1:65536'])assert.throws(()=>create({env:{...fixture().env,CT_SSO_CONNECT_ADDRESS:address}}));
});
test('bounded read cache, forced write checks, refresh rotation and outages never bypass authentication',async()=>{
 const f=fixture(),s=await f.login();assert.equal(f.stats().introspections,1);await f.adapter.validate(s);assert.equal(f.stats().introspections,1);
 f.advance(880000);await Promise.all([f.adapter.validate(s,true),f.adapter.validate(s,true)]);assert.equal(f.stats().refreshes,1,'concurrent validation shares one refresh exchange');
 f.revoke();await assert.rejects(f.adapter.validate(s,true),e=>e.status===401);
 const g=fixture(),session=await g.login();g.offline();await assert.rejects(g.adapter.validate(session,true),e=>e.status===503);
 g.advance(5001);await assert.rejects(g.adapter.validate(session),e=>e.status===503);
});
test('login flow storage is bounded, browser and IP bound, expires and prevents replay',async()=>{
 const f=fixture();for(let i=0;i<64;i++)f.adapter.start({headers:{}},'ip');assert.throws(()=>f.adapter.start({headers:{}},'ip'),e=>e.status===429);f.advance(300001);f.adapter.start({headers:{}},'ip');
 const g=fixture(),start=g.adapter.start({headers:{}},'ip'),auth=new URL(start.location),url=new URL('https://datahub.example/tunnel/sso/callback?code=code_'+'x'.repeat(32)+'&state='+auth.searchParams.get('state'));
 await assert.rejects(g.adapter.complete({headers:{cookie:start.cookie.split(';')[0]}},url,'different-ip'),e=>e.status===400);
 await assert.rejects(g.adapter.complete({headers:{cookie:start.cookie.split(';')[0]+'; '+start.cookie.split(';')[0]}},url,'ip'),e=>e.status===400);
});
