'use strict';
const crypto=require('node:crypto');
const routePath=require('./route-path.cjs');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
const signature=r=>JSON.stringify([routePath.relays(r),r.transport,r.serverName||'']);
function normalize(input,route,validate){
 if(input===undefined)return [];
 if(!Array.isArray(input)||input.length>8)fail('每个方向最多添加 8 条备线');
 const ids=new Set(),paths=new Set([signature(route)]);
 return input.map((value,index)=>{
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['id','name','relayIds','transport','serverName','direct'].includes(k)))fail('备线参数不正确');
  const id=value.id||'backup-'+crypto.randomBytes(8).toString('hex');
  if(!/^backup-[a-f0-9]{16}$/.test(id)||ids.has(id))fail('备线标识无效或重复');ids.add(id);
  const name=String(value.name||'备线 '+(index+1)).trim();if(!name||name.length>60)fail('备线名称须为 1–60 字符');
  if(!Array.isArray(value.relayIds))fail('请选择备线经过的优化机');
  if(value.direct!==undefined&&typeof value.direct!=='boolean')fail('direct 必须为布尔值');
  const candidate=validate({...route,...value,id:undefined,backupPaths:undefined,name:route.name,direct:value.direct===true||value.relayIds.length===0,relayId:value.relayIds[0],transport:value.transport||route.transport,serverName:value.serverName??route.serverName});
  const key=signature(candidate);if(paths.has(key))fail('备线不能与主线或其他备线重复');paths.add(key);
  return {id,name,relayIds:[...routePath.relays(candidate)],transport:candidate.transport,serverName:candidate.serverName,...(candidate.direct?{direct:true}:{})};
 });
}
function expand(route){
 const backups=(route.backupPaths||[]).map(p=>({...route,...p,direct:p.direct===true,id:route.id+'~'+p.id,name:route.name+' · '+p.name,parentRouteId:route.id,listenPort:0,relayId:p.relayIds[0],relayIds:[...p.relayIds],backupPaths:undefined,fallbackRouteIds:undefined}));
 const primary={...route,backupPaths:undefined,...(backups.length?{fallbackRouteIds:backups.map(b=>b.id)}:{})};
 return [primary,...backups];
}
const all=state=>state.routes.flatMap(expand);
const nodeIds=route=>[...new Set(expand(route).flatMap(routePath.path))];
function report(state,nodeId,incoming,now=Date.now()){
 const out={};
 for(const r of state.routes.filter(r=>r.source===nodeId&&r.backupPaths?.length)){
  const raw=incoming?.[r.id];if(!raw||typeof raw!=='object')continue;
  const ids=expand(r).map(p=>p.id),paths={};
  for(const id of ids){const p=raw.paths?.[id];if(!p||typeof p!=='object')continue;const checkedAt=Number(p.checkedAt);paths[id]={healthy:p.healthy===true&&Number.isSafeInteger(checkedAt)&&checkedAt<=now+5000&&checkedAt>=now-30000,checkedAt:Number.isSafeInteger(checkedAt)?checkedAt:0,failures:Math.max(0,Math.min(1000000,Number(p.failures)||0))};}
  out[r.id]={activePathId:ids.includes(raw.activePathId)?raw.activePathId:r.id,switches:Math.max(0,Math.min(1e9,Number(raw.switches)||0)),switchedAt:Number(raw.switchedAt)||0,paths};
 }
 return out;
}
module.exports={normalize,expand,all,nodeIds,report};
