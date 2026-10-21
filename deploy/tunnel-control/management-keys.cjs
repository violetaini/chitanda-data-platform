'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const SCOPES=['status:read','nodes:read','nodes:write','tunnels:read','tunnels:write','checks:write'];
const fail=(message,status=400,extra={})=>{throw Object.assign(Error(message),{status,...extra});};
module.exports=function(directory,{now=Date.now}={}){
 const file=path.join(directory,'management-keys.json'),hash=s=>crypto.createHash('sha256').update(s).digest('hex');
 let records=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):[];
 const save=()=>{fs.writeFileSync(file+'.tmp',JSON.stringify(records),{mode:0o600});fs.renameSync(file+'.tmp',file);};
 const safe=k=>({id:k.id,name:k.name,prefix:k.prefix,scopes:k.scopes,createdAt:k.createdAt,expiresAt:k.expiresAt,lastUsedAt:k.lastUsedAt||null,expired:Date.parse(k.expiresAt)<=now()});
 const buckets=new Map();
 function quota(id,limit){const t=now();if(buckets.size>1024)for(const [k,v]of buckets)if(v.start+60000<=t)buckets.delete(k);let b=buckets.get(id);if(!b||b.start+60000<=t){b={start:t,count:0};buckets.set(id,b);}if(b.count>=limit)fail('API 请求过于频繁',429,{retryAfter:Math.max(1,Math.ceil((b.start+60000-t)/1000))});b.count++;}
 function active(k){return records.includes(k)&&Date.parse(k.expiresAt)>now();}
 return {
  list:()=>({keys:records.map(safe),scopes:SCOPES}),active,
  create(input){
   if(Object.keys(input).some(k=>!['name','scopes','expiresInDays'].includes(k)))fail('API 密钥参数不正确');
   const name=String(input.name||'').trim(),days=input.expiresInDays??30,scopes=input.scopes;
   if(!name||name.length>60)fail('请填写 1–60 字符的密钥名称');
   if(!Number.isInteger(days)||days<1||days>365)fail('有效期应为 1–365 天');
   if(!Array.isArray(scopes)||!scopes.length||scopes.some(s=>!SCOPES.includes(s)))fail('请选择有效的 API 权限');
   if(records.length>=64)fail('最多保留 64 个 API 密钥，请先撤销不使用的密钥');
   const id=crypto.randomBytes(8).toString('hex'),secret='ctm_'+id+'_'+crypto.randomBytes(32).toString('hex'),k={id,name,prefix:'ctm_'+id,hash:hash(secret),scopes:[...new Set(scopes)],createdAt:new Date(now()).toISOString(),expiresAt:new Date(now()+days*86400000).toISOString()};
   const before=records;records=records.concat(k);try{save();}catch(e){records=before;throw e;}return {key:safe(k),secret};
  },
  revoke(id){const k=records.find(v=>v.id===id);if(!k)fail('密钥不存在',404);const before=records;records=records.filter(v=>v!==k);try{save();}catch(e){records=before;throw e;}return safe(k);},
  authorize(req,scope,ip){
   quota('ip:'+ip,240);
   const value=String(req.headers.authorization||''),match=value.match(/^Bearer (ctm_([a-f0-9]{16})_[a-f0-9]{64})$/),k=match&&records.find(v=>v.id===match[2]);
   if(!k||!crypto.timingSafeEqual(Buffer.from(k.hash,'hex'),Buffer.from(hash(match[1]),'hex'))||!active(k))fail('API 密钥无效、已过期或已撤销',401);
   const read=['GET','HEAD'].includes(req.method);quota('key:'+k.id+(read?':read':':write'),read?120:30);
   if(scope&&!k.scopes.includes(scope))fail('API 密钥缺少权限：'+scope,403);
   if(!k.lastUsedAt||now()-Date.parse(k.lastUsedAt)>=60000){k.lastUsedAt=new Date(now()).toISOString();save();}
   return k;
  }
 };
};
