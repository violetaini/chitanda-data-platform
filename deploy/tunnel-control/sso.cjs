'use strict';
// Server-side OIDC: never accept browser identity headers or SSO tokens as API keys.
const crypto=require('node:crypto'),https=require('node:https'),tls=require('node:tls'),net=require('node:net'),{Readable}=require('node:stream');
const random=()=>crypto.randomBytes(32).toString('base64url');
const failure=(message,status=401)=>Object.assign(Error(message),{status});
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function cookie(req,name){const values=String(req.headers.cookie||'').split(';').map(s=>s.trim()).filter(s=>s.startsWith(name+'='));return values.length===1?values[0].slice(name.length+1):'';}
module.exports=function({env=process.env,fetchImpl=fetch,now=Date.now}={}){
 const enabled=env.CT_AUTH_MODE==='sso';
 if(!enabled){if(env.CT_AUTH_MODE&&!['local','sso'].includes(env.CT_AUTH_MODE))throw Error('Invalid authentication mode');return {enabled:false};}
 const issuer=new URL(env.CT_SSO_ISSUER||'https://sso.chitanda.net'),origin=new URL(env.CT_CONTROLLER_URL||'https://datahub.chitanda.net');
 const insecure=env.CT_INSECURE==='1';
 if(env.CT_SSO_CONNECT_ADDRESS){
  const destination=new URL('tls://'+env.CT_SSO_CONNECT_ADDRESS),address=destination.hostname.replace(/^\[|\]$/g,'');
  if(!net.isIP(address)||!destination.port||destination.username||destination.password||destination.pathname||destination.search||destination.hash||issuer.protocol!=='https:')throw Error('Invalid SSO backchannel address');
  const agent=new https.Agent({keepAlive:true,maxSockets:4,maxFreeSockets:2});
  fetchImpl=(url,options)=>new Promise((resolve,reject)=>{
   const req=https.request({hostname:address,port:Number(destination.port),servername:issuer.hostname,checkServerIdentity:(_,cert)=>tls.checkServerIdentity(issuer.hostname,cert),rejectUnauthorized:true,path:url.pathname+url.search,method:options.method,agent,signal:options.signal,headers:{...options.headers,Host:issuer.host}},res=>resolve(new Response(Readable.toWeb(res),{status:res.statusCode,headers:res.headers})));
   req.on('error',reject);req.end(options.body);
  });
 }
 for(const u of [issuer,origin])if(u.username||u.password||u.search||u.hash||u.pathname!=='/'||(u.protocol!=='https:'&&!(insecure&&u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname))))throw Error('Invalid SSO endpoint');
 const clientId=env.CT_SSO_CLIENT_ID||'data-platform',clientSecret=env.CT_SSO_CLIENT_SECRET||'',subjects=new Set((env.CT_SSO_ADMIN_SUBJECTS||'').split(',').filter(Boolean));
 if(clientSecret.length<32||!subjects.size||[...subjects].some(v=>!/^usr_[a-zA-Z0-9_-]{1,96}$/.test(v)))throw Error('SSO client secret and explicit administrator subjects are required');
 const callback=origin.origin+'/tunnel/sso/callback',flows=new Map();let jwks=null,jwksUntil=0,jwksPending=null;
 const flowCookie=value=>`ct_sso_flow=${value}; Path=/tunnel/; HttpOnly; SameSite=Lax; Max-Age=${value?300:0}${insecure?'':'; Secure'}`;
 async function request(path,{form,headers={}}={}){
  let response;try{response=await fetchImpl(new URL(path,issuer),{method:form?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(8000),headers:{Accept:'application/json',...headers,...(form?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(form?{body:new URLSearchParams(form).toString()}:{})});}catch(e){console.error('SSO transport unavailable:',path,e.name,e.cause?.code||'');throw failure('统一登录暂时不可用，请稍后重试',503);}
  if(!response.ok){console.error('SSO endpoint rejected:',path,response.status);await response.body?.cancel();throw failure(response.status>=500?'统一登录暂时不可用，请稍后重试':'统一登录验证失败',response.status>=500?503:401);}
  let total=0,chunks=[];const timer=setTimeout(()=>response.body?.cancel().catch(()=>{}),4000);try{for await(const chunk of response.body){total+=chunk.length;if(total>65536)throw Error('large');chunks.push(Buffer.from(chunk));}return JSON.parse(Buffer.concat(chunks).toString());}catch{console.error('SSO invalid response:',path,total);throw failure('统一登录响应无效',503);}finally{clearTimeout(timer);}
 }
 async function keys(){if(jwks&&jwksUntil>now())return jwks;if(!jwksPending)jwksPending=request('/.well-known/jwks.json').then(v=>{if(!Array.isArray(v.keys)||v.keys.length>16)throw failure('统一登录公钥无效',503);jwks=v.keys;jwksUntil=now()+300000;return jwks;}).finally(()=>jwksPending=null);return jwksPending;}
 async function verifyIdToken(token,nonce){
  try{
   if(typeof token!=='string'||token.length>16384)throw Error();const parts=token.split('.');if(parts.length!==3||parts.some(s=>!s||!/^[a-zA-Z0-9_-]+$/.test(s)))throw Error();
   const header=JSON.parse(Buffer.from(parts[0],'base64url')),claims=JSON.parse(Buffer.from(parts[1],'base64url'));if(header.alg!=='RS256'||typeof header.kid!=='string'||header.crit)throw Error();
   const key=(await keys()).find(k=>k.kid===header.kid&&k.kty==='RSA'&&k.alg==='RS256'&&k.use==='sig');if(!key||!crypto.verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),crypto.createPublicKey({key,format:'jwk'}),Buffer.from(parts[2],'base64url')))throw Error();
   const t=Math.floor(now()/1000);if(claims.iss!==issuer.origin||claims.aud!==clientId||(nonce!==undefined&&claims.nonce!==nonce)||claims.token_use!=='id'||typeof claims.sid!=='string'||!Number.isFinite(claims.exp)||claims.exp<=t||!Number.isFinite(claims.iat)||claims.iat>t+30||t-claims.iat>300||(claims.nbf!==undefined&&(!Number.isFinite(claims.nbf)||claims.nbf>t+30)))throw Error();
   return claims;
  }catch(e){if(e.status===503)throw e;throw failure('统一登录身份校验失败');}
 }
 const authorized=user=>subjects.has(user.sub)&&Array.isArray(user.roles)&&user.roles.some(r=>r==='admin'||r==='root');
 function start(req,ip){
  for(const [k,f]of flows)if(f.until<=now())flows.delete(k);
  const previous=cookie(req,'ct_sso_flow');if(previous)for(const [k,f]of flows)if(f.browser===digest(previous))flows.delete(k);
  if(flows.size>=64)throw failure('登录请求过多，请稍后重试',429);
  const state=random(),browser=random(),nonce=random(),verifier=random();flows.set(state,{browser:digest(browser),nonce,verifier,ip,until:now()+300000});
  const u=new URL('/oauth/authorize',issuer);u.search=new URLSearchParams({client_id:clientId,redirect_uri:callback,response_type:'code',scope:'openid profile tunnel:admin',state,nonce,code_challenge:crypto.createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}).toString();
  return {location:u.href,cookie:flowCookie(browser)};
 }
 async function complete(req,url,ip){
  const state=url.searchParams.get('state'),code=url.searchParams.get('code'),browser=cookie(req,'ct_sso_flow'),flow=flows.get(state);
  if(!state||url.searchParams.getAll('state').length!==1||!flow||flow.until<=now()||flow.ip!==ip||!browser||flow.browser!==digest(browser))throw failure('登录请求已失效，请重新登录',400);
  flows.delete(state);
  if(url.searchParams.has('error')||url.searchParams.getAll('code').length!==1||typeof code!=='string'||!/^code_[a-zA-Z0-9_-]{20,128}$/.test(code))throw failure('统一登录未完成，请重新登录',400);
  const tokens=await request('/oauth/token',{form:{grant_type:'authorization_code',client_id:clientId,client_secret:clientSecret,redirect_uri:callback,code,code_verifier:flow.verifier}});
  const identity=await verifyIdToken(tokens.id_token,flow.nonce);
  if(typeof tokens.access_token!=='string'||tokens.access_token.length>16384)throw failure('统一登录凭据无效');
  if(typeof tokens.refresh_token!=='string'||tokens.refresh_token.length>512)throw failure('统一登录刷新凭据无效');
  const session={sso:{subject:identity.sub,sid:identity.sid,accessToken:tokens.access_token,refreshToken:tokens.refresh_token,expires:identity.exp*1000,identity,checkedUntil:0},until:now()+43200000};
  await validate(session,true);return {session,cookie:flowCookie('')};
 }
 async function validate(session,force=false){
  if(!session?.sso||session.until<=now())throw failure('统一登录已过期，请重新登录');
  const s=session.sso;if(!force&&s.checkedUntil>now())return;
  if(!s.pending)s.pending=(async()=>{
   if(s.expires<=now()+30000){
    const tokens=await request('/oauth/token',{form:{grant_type:'refresh_token',client_id:clientId,client_secret:clientSecret,refresh_token:s.refreshToken}}),identity=await verifyIdToken(tokens.id_token);
    if(identity.sub!==s.subject||identity.sid!==s.sid||typeof tokens.access_token!=='string'||tokens.access_token.length>16384||typeof tokens.refresh_token!=='string'||tokens.refresh_token.length>512)throw failure('统一登录刷新验证失败');
    s.accessToken=tokens.access_token;s.refreshToken=tokens.refresh_token;s.expires=identity.exp*1000;
   }
   const info=await request('/oauth/introspect',{form:{client_id:clientId,client_secret:clientSecret,token:s.accessToken}});
   if(info.active!==true||info.sub!==s.subject||info.sid!==s.sid||info.client_id!==clientId||!Number.isFinite(info.exp)||info.exp*1000<=now()||!authorized(info))throw failure('统一登录已失效或没有中台管理权限',401);
   s.identity={sub:info.sub,username:String(info.username||''),name:String(info.name||info.username||''),roles:info.roles};s.checkedUntil=now()+5000;
  })().finally(()=>s.pending=null);
  await s.pending;
 }
 const profile=session=>({username:session.sso.identity.username,displayName:session.sso.identity.name,authMode:'sso',accountUrl:issuer.origin+'/portal'});
 function logoutUrl(){const u=new URL('/oauth/logout',issuer);u.searchParams.set('post_logout_redirect_uri',origin.origin+'/tunnel/?loggedout=1');return u.href;}
 return {enabled,start,complete,validate,profile,logoutUrl,loginUrl:'/tunnel/sso/start',accountUrl:issuer.origin+'/portal',clearFlow:()=>flowCookie('')};
};
