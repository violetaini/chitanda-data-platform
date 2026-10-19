'use strict';
// Published bindings opt into address maintenance. State survives restarts;
// retries never create records or publish a pending TTL / draft binding.
function targets(state,binding){
 const tunnel=state.tunnels?.find(t=>t.id===binding.tunnelId);
 return (tunnel?.routeIds||[]).map(id=>{const route=state.routes.find(r=>r.id===id),node=[...state.nodes,...state.relays].find(n=>n.id===route?.source);return {routeId:id,nodeId:node?.id,host:node?.host};});
}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function summary(state,binding){
 if(binding.status!=='published')return null;
 const stored=binding.addressSync||{},current=targets(state,binding);
 const pending=!same(stored.targets,current);
 return {automatic:true,status:stored.lastError&&same(stored.attemptedTargets,current)?'error':pending?'pending':'synced',checkedAt:stored.checkedAt,updatedAt:stored.updatedAt,retryAt:stored.retryAt,lastError:stored.lastError&&same(stored.attemptedTargets,current)?stored.lastError:undefined};
}
module.exports=function({getState,syncAddresses,isBusy,save,audit,now=Date.now}){
 let running=false;
 async function tick(){
  if(running||isBusy())return;running=true;
  try{
   for(const binding of getState().domains||[]){
    if(binding.status!=='published'||isBusy())continue;
    const current=targets(getState(),binding),old=binding.addressSync||{},time=now();
    if(same(old.attemptedTargets,current)&&Date.parse(old.retryAt)>time)continue;
    if(same(old.targets,current)&&!old.lastError&&Date.parse(old.checkedAt)>time-300000)continue;
    try{
     const result=await syncAddresses(binding.id),changed=result.changes.update.length>0;
     // Capture only addresses actually checked. A later heartbeat is handled
     // in the next pass, never recorded as already published.
     binding.addressSync={targets:current,attemptedTargets:current,checkedAt:new Date(now()).toISOString(),...(old.updatedAt?{updatedAt:old.updatedAt}:{}),...(changed?{updatedAt:new Date(now()).toISOString()}:{})};save();
    }catch(error){
     const message=String(error.message||'DNS 自动更新失败').slice(0,300),failures=same(old.attemptedTargets,current)?Math.min((old.failures||0)+1,10):1;
     binding.addressSync={...old,attemptedTargets:current,lastError:message,failures,retryAt:new Date(now()+Math.min(300000,30000*2**(failures-1))).toISOString()};
     if(old.lastError!==message||!same(old.attemptedTargets,current))audit('节点解析自动更新待处理',binding.domain+' · '+message);else save();
    }
   }
  }finally{running=false;}
 }
 return {tick};
};
module.exports.summary=summary;
module.exports.targets=targets;
