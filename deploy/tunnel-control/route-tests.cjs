'use strict';
const crypto=require('node:crypto'),fs=require('node:fs');
const busy=s=>s==='queued'||s==='running';
const reasons=['source-unavailable','timeout','target-unavailable','target-offline','not-permitted','channel-unavailable'];
module.exports=function createRouteTests({getState,getReport,getSettings=()=>({enabled:true,intervalSeconds:60,maxAgeSeconds:180}),now=Date.now,storageFile}){
 const jobs=new Map(),results=new Map();
 const error=(message,status=409)=>{throw Object.assign(Error(message),{status});};
 const validSamples=s=>Array.isArray(s)&&s.length<=3&&s.every(n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=30000);
 const view=j=>j?{id:j.id,routeId:j.routeId,revision:j.revision,trigger:j.trigger||'manual',status:j.status,reason:j.reason||'',createdAt:j.createdAt,startedAt:j.startedAt||'',finishedAt:j.finishedAt||'',attempts:j.attempts||0,successes:j.samples?.length||0,samples:[...(j.samples||[])],latency:j.samples?.length?{min:Math.min(...j.samples),max:Math.max(...j.samples),average:j.samples.reduce((s,n)=>s+n,0)/j.samples.length}:null}:null;
 function persist(){
  if(!storageFile)return;
  try{fs.writeFileSync(storageFile+'.tmp',JSON.stringify({version:1,results:[...results.values()].map(view)}),{mode:0o600});fs.chmodSync(storageFile+'.tmp',0o600);fs.renameSync(storageFile+'.tmp',storageFile);}
  catch{console.error('route check cache write failed');}
 }
 if(storageFile&&fs.existsSync(storageFile)){
  try{
   if(fs.statSync(storageFile).size>524288)throw Error('oversized');
   const cache=JSON.parse(fs.readFileSync(storageFile,'utf8'));
   if(cache.version!==1||!Array.isArray(cache.results))throw Error('invalid');
   for(const raw of cache.results.slice(0,128)){
    if(!raw||!getState().routes.some(r=>r.id===raw.routeId)||typeof raw.id!=='string'||!/^check-[a-f0-9]{32}$/.test(raw.id)||!Number.isInteger(raw.revision)||!['success','partial','failed','timeout'].includes(raw.status)||!validSamples(raw.samples)||!Number.isInteger(raw.attempts)||raw.attempts<raw.samples.length||raw.attempts>3||raw.attempts<0||!Number.isFinite(Date.parse(raw.createdAt))||!Number.isFinite(Date.parse(raw.finishedAt))||Date.parse(raw.finishedAt)>now()+60000)continue;
    const count=raw.samples.length;
    if(raw.status!==(count===3?'success':count?'partial':raw.status==='timeout'?'timeout':'failed'))continue;
    const result={...view(raw),trigger:raw.trigger==='automatic'?'automatic':'manual',reason:reasons.includes(raw.reason)?raw.reason:'',created:Date.parse(raw.createdAt)};
    results.set(raw.routeId,result);jobs.set(raw.routeId,{...result});
   }
  }catch{console.error('route check cache ignored: invalid data');}
 }
 function finish(j,status,reason){
  j.status=status;j.reason=reason||'';j.finishedAt=new Date(now()).toISOString();
  if(status!=='cancelled')results.set(j.routeId,{...j,samples:[...j.samples]});
  persist();
 }
 function sweep(){
  const state=getState(),time=now(),ids=new Set(state.routes.map(r=>r.id));let pruned=false;
  for(const id of results.keys())if(!ids.has(id)){results.delete(id);pruned=true;}
  for(const [id,j]of jobs){
   if(!ids.has(id)){jobs.delete(id);continue;}
   if(busy(j.status)&&j.revision!==state.version)finish(j,'cancelled','config-changed');
   else if(busy(j.status)&&time>=j.expires)finish(j,'timeout','timeout');
  }
  if(pruned)persist();
 }
 function completed(j){
  const result=view(j);if(!result)return null;
  if(j.revision!==getState().version)result.status='stale';
  result.expired=now()-Date.parse(j.finishedAt)>getSettings().maxAgeSeconds*1000;
  return result;
 }
 function get(routeId){
  sweep();const j=jobs.get(routeId);
  if(!j)return completed(results.get(routeId));
  if(busy(j.status)||j.status==='cancelled')return {...view(j),lastResult:completed(results.get(routeId))};
  return completed(j);
 }
 function create(route,trigger='manual'){
  sweep();const state=getState(),time=now(),previous=jobs.get(route.id);
  if(!route.enabled)error('请先启用该数据通道');
  // A manual click can take over an automatic check already using this exact path.
  if(previous&&busy(previous.status)){
   if(trigger==='manual'&&previous.trigger==='automatic'){previous.trigger='manual';return get(route.id);}
   error('该数据通道正在测试中');
  }
  if(previous&&time-previous.created<10000)error('请间隔 10 秒后重试',429);
  for(const id of new Set([route.source,route.relayId,route.target])){const r=getReport(id);if(!r.online)error('相关节点离线，暂时无法测试');if(r.revision!==state.version)error('节点配置同步中，请稍后测试');if(r.capabilities?.routeProbe!==1)error('相关节点尚未支持线路测试，请先升级节点');}
  const active=[...jobs.values()].filter(j=>busy(j.status));if(active.length>=4)error('当前测试较多，请稍后重试',429);if(active.some(j=>j.source===route.source))error('源节点正在执行其他测试，请稍后重试',429);
  jobs.set(route.id,{id:'check-'+crypto.randomBytes(16).toString('hex'),routeId:route.id,source:route.source,revision:state.version,trigger,status:'queued',created:time,expires:time+90000,createdAt:new Date(time).toISOString(),samples:[]});return get(route.id);
 }
 return {
  create,get,
  tick(){
   sweep();const time=now(),state=getState(),settings=getSettings();if(!settings.enabled)return;
   // Oldest result first prevents large configurations sharing a source from starving.
   const routes=state.routes.filter(r=>r.enabled).sort((a,b)=>(Date.parse(results.get(a.id)?.finishedAt)||0)-(Date.parse(results.get(b.id)?.finishedAt)||0));
   for(const route of routes){const j=jobs.get(route.id),last=results.get(route.id);if(j&&busy(j.status))continue;if(last&&last.revision===state.version&&time-Date.parse(last.finishedAt)<settings.intervalSeconds*1000)continue;try{create(route,'automatic');}catch(e){if(!e.status)throw e;}}
  },
  pending(nodeId){sweep();return [...jobs.values()].filter(j=>j.source===nodeId&&busy(j.status)).slice(0,1).map(j=>{j.status='running';j.startedAt||=new Date(now()).toISOString();return {id:j.id,routeId:j.routeId,revision:j.revision,expiresAt:new Date(j.expires).toISOString()};});},
  accept(nodeId,incoming){
   sweep();if(!Array.isArray(incoming))return;
   for(const raw of incoming.slice(0,32)){
    const j=[...jobs.values()].find(j=>j.id===raw?.id&&j.routeId===raw.routeId&&j.source===nodeId);if(!j||!busy(j.status)||j.revision!==raw.revision)continue;
    if(raw.status==='cancelled'){finish(j,'cancelled','config-changed');continue;}
    if(raw.status!=='complete'||!Number.isInteger(raw.attempts)||raw.attempts<0||(raw.attempts===0&&raw.reason!=='source-unavailable')||raw.attempts>3||!validSamples(raw.samples)||raw.samples.length>raw.attempts)continue;
    j.attempts=raw.attempts;j.samples=[...raw.samples];finish(j,j.samples.length===3?'success':j.samples.length?'partial':'failed',reasons.includes(raw.reason)?raw.reason:'');
   }
  }
 };
};
