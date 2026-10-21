'use strict';
const crypto=require('node:crypto');
function roles(value){
 if(typeof value==='string'){try{value=JSON.parse(value);}catch{return [];}}
 return Array.isArray(value)?value.filter(r=>typeof r==='string'&&/^[a-zA-Z0-9:_-]{1,64}$/.test(r)):[];
}
function exactRedirect(value,registered){
 if(typeof value!=='string'||!Array.isArray(registered))return false;
 try{const u=new URL(value);if(u.hash||u.username||u.password||!(u.protocol==='https:'||(u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname))))return false;return registered.includes(value);}catch{return false;}
}
function safeLogout(value,issuer,clients){
 try{if(!value)return '/login';const u=new URL(value,issuer);if(u.username||u.password||u.hash||u.protocol!=='https:')return '/login';if(u.origin===issuer)return u.href;
  for(const client of clients)for(const uri of client.redirect_uris||[]){const r=new URL(uri);if(u.origin===r.origin&&((u.pathname==='/tunnel/'&&r.pathname==='/tunnel/sso/callback')||u.pathname===r.pathname))return u.href;}
 }catch{}return '/login';
}
function equal(a,b){return typeof a==='string'&&typeof b==='string'&&crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(),crypto.createHash('sha256').update(b).digest());}
function safeAppUrl(value){try{if(typeof value!=='string'||value.length>2048)return false;const u=new URL(value);return !u.username&&!u.password&&(u.protocol==='https:'||(u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname)));}catch{return false;}}
module.exports={roles,exactRedirect,safeLogout,equal,safeAppUrl};
