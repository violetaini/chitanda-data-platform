'use strict';
const crypto=require('node:crypto');
module.exports=function createRouteTests({getState,getReport,now=Date.now}){
 const jobs=new Map(),busy=s=>s==='queued'||s==='running';
 const error=(message,status=409)=>{throw Object.assign(Error(message),{status});};
 const sweep=()=>{const state=getState(),time=now();for(const [routeId,j]of jobs){if(!state.routes.some(r=>r.id===routeId)){jobs.delete(routeId);continue;}if(busy(j.status)&&j.revision!==state.version){j.status='cancelled';j.reason='config-changed';j.finishedAt=new Date(time).toISOString();}else if(busy(j.status)&&time>=j.expires){j.status='timeout';j.reason='timeout';j.finishedAt=new Date(time).toISOString();}}};
 const view=j=>j?{id:j.id,routeId:j.routeId,revision:j.revision,status:j.status,reason:j.reason||'',createdAt:j.createdAt,startedAt:j.startedAt||'',finishedAt:j.finishedAt||'',attempts:j.attempts||0,successes:j.samples?.length||0,samples:j.samples||[],latency:j.samples?.length?{min:Math.min(...j.samples),max:Math.max(...j.samples),average:j.samples.reduce((s,n)=>s+n,0)/j.samples.length}:null}:null;
 return {
  create(route){
   sweep();const state=getState(),time=now(),previous=jobs.get(route.id);
   if(!route.enabled)error('请先启用该数据通道');
   if(previous&&busy(previous.status))error('该数据通道正在测试中');
   if(previous&&time-previous.created<10000)error('请间隔 10 秒后重试',429);
   for(const id of new Set([route.source,route.relayId,route.target])){const r=getReport(id);if(!r.online)error('相关节点离线，暂时无法测试');if(r.revision!==state.version)error('节点配置同步中，请稍后测试');if(r.capabilities?.routeProbe!==1)error('相关节点尚未支持线路测试，请先升级节点');}
   const active=[...jobs.values()].filter(j=>busy(j.status));if(active.length>=4)error('当前测试较多，请稍后重试',429);if(active.some(j=>j.source===route.source))error('源节点正在执行其他测试，请稍后重试',429);
   const job={id:'check-'+crypto.randomBytes(16).toString('hex'),routeId:route.id,source:route.source,revision:state.version,status:'queued',created:time,expires:time+90000,createdAt:new Date(time).toISOString(),samples:[]};jobs.set(route.id,job);return view(job);
  },
  pending(nodeId){sweep();const time=now();return [...jobs.values()].filter(j=>j.source===nodeId&&busy(j.status)).slice(0,1).map(j=>{j.status='running';j.startedAt||=new Date(time).toISOString();return {id:j.id,routeId:j.routeId,revision:j.revision,expiresAt:new Date(j.expires).toISOString()};});},
  accept(nodeId,results){
   sweep();if(!Array.isArray(results))return;
   for(const raw of results.slice(0,32)){
    const j=[...jobs.values()].find(j=>j.id===raw?.id&&j.routeId===raw.routeId&&j.source===nodeId);if(!j||!busy(j.status)||j.revision!==raw.revision)continue;
    if(raw.status==='cancelled'){j.status='cancelled';j.reason='config-changed';j.finishedAt=new Date(now()).toISOString();continue;}
    if(raw.status!=='complete'||!Number.isInteger(raw.attempts)||raw.attempts<0||(raw.attempts===0&&raw.reason!=='source-unavailable')||raw.attempts>3||!Array.isArray(raw.samples)||raw.samples.length>raw.attempts)continue;
    if(raw.samples.some(n=>typeof n!=='number'||!Number.isFinite(n)||n<0||n>30000))continue;
    j.attempts=raw.attempts;j.samples=raw.samples;j.status=j.samples.length===3?'success':j.samples.length?'partial':'failed';j.reason=['source-unavailable','timeout','target-unavailable','target-offline','not-permitted','channel-unavailable'].includes(raw.reason)?raw.reason:'';j.finishedAt=new Date(now()).toISOString();
   }
  },
  get(routeId){sweep();const j=jobs.get(routeId),result=view(j);if(result&&j.revision!==getState().version&&!busy(j.status)&&j.status!=='cancelled')result.status='stale';return result;}
 };
};
