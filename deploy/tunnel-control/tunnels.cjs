'use strict';
const crypto=require('node:crypto');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
// Tunnels are control-plane objects; route IDs and node wire configuration stay intact.
function normalize(state){
 state.tunnels||=[];
 for(const b of state.domains||[]){
  if(b.tunnelId&&state.tunnels.some(t=>t.id===b.tunnelId))continue;
  const a=state.routes.find(r=>r.id===b.mainlandRouteId),z=state.routes.find(r=>r.id===b.internationalRouteId);
  if(!a)continue;
  const pair=z&&a.id!==z.id&&a.source===z.target&&a.target===z.source;
  if(!pair&&z)fail('旧域名绑定不是互为反向的线路，请先核对配置',409);
  const ids=pair?[a.id,z.id]:[a.id];
  const existing=state.tunnels.find(t=>ids.every(id=>t.routeIds.includes(id)));
  if(existing){b.tunnelId=existing.id;continue;}
  if(state.tunnels.some(t=>t.routeIds.some(id=>ids.includes(id))))fail('旧域名绑定与隧道分组冲突',409);
  const t={id:'tunnel-'+b.id,name:pair?'双向业务隧道':a.name,mode:pair?'bidirectional':'single',routeIds:ids,createdAt:b.createdAt||a.createdAt};
  state.tunnels.push(t);b.tunnelId=t.id;
 }
 state.tunnels=state.tunnels.filter(t=>t.routeIds.every(id=>state.routes.some(r=>r.id===id)));
 for(const r of state.routes){if(state.tunnels.some(t=>t.routeIds.includes(r.id)))continue;state.tunnels.push({id:r.id,name:r.name,mode:'single',routeIds:[r.id],createdAt:r.createdAt});}
 for(const t of state.tunnels)if(t.mode==='single')t.name=state.routes.find(r=>r.id===t.routeIds[0])?.name||t.name;
 return state.tunnels;
}
module.exports=function({getState,validateRoute,ensureCertificates,audit}){
 const get=id=>{const t=normalize(getState()).find(t=>t.id===id);if(!t)fail('隧道不存在',404);return t;};
 const bound=t=>(getState().domains||[]).some(b=>b.tunnelId===t.id||t.routeIds.some(id=>[b.mainlandRouteId,b.internationalRouteId].includes(id)));
 function write(input,id){
  const s=getState(),old=id?get(id):null,mode=input.mode||old?.mode||'single',name=String(input.name||old?.name||'').trim();
  if(!['single','bidirectional'].includes(mode)||!name||name.length>60)fail('请选择隧道类型并填写 1–60 字符的名称');
  if(old&&bound(old)&&mode!==old.mode)fail('已绑定域名的隧道不能直接改变单双向类型',409);
  const count=mode==='bidirectional'?2:1;if(s.routes.length-(old?.routeIds.length||0)+count>128)fail('最多配置 128 条底层线路');
  const before=s.routes,previousRelays=s.relays,previousNodes=s.nodes,previousTunnels=structuredClone(normalize(s));s.relays=structuredClone(s.relays);s.nodes=structuredClone(s.nodes);
  try{
   const first=old&&before.find(r=>r.id===old.routeIds[0]);
   const values={...first,...input,name,enabled:input.enabled??first?.enabled??true};
   const a=validateRoute(values,old?.routeIds[0]);
   s.routes=before.filter(r=>!old?.routeIds.includes(r.id)).concat(a);
   const ids=[a.id];
   if(count===2){
    const prev=old&&before.find(r=>r.id===old.routeIds[1]);
    // Keep the old reverse route visible to endpoint guards while validating.
    if(prev)s.routes.push(prev);
    const b=validateRoute({...values,...prev,...input,name,enabled:values.enabled,source:a.target,target:a.source,direct:a.direct===true,listenPort:input.reverseListenPort??prev?.listenPort??a.listenPort,targetPort:input.reverseTargetPort??prev?.targetPort??a.targetPort,...(a.relayIds?{relayIds:[...a.relayIds].reverse(),relayId:a.relayIds.at(-1)}:{})},prev?.id);
    s.routes=s.routes.filter(r=>r.id!==b.id).concat({...b,createdAt:prev?.createdAt||b.createdAt});ids.push(b.id);
   }
   s.routes=s.routes.map(r=>r.id===a.id?{...r,createdAt:first?.createdAt||r.createdAt}:r);
   ensureCertificates();
   const t={id:old?.id||'tunnel-'+crypto.randomBytes(8).toString('hex'),name,mode,routeIds:ids,createdAt:old?.createdAt||new Date().toISOString()};
   s.tunnels=previousTunnels.map(v=>v.id===old?.id?t:v);if(!old)s.tunnels.push(t);
   s.version++;audit(old?'更新隧道':'创建隧道',name+' · '+(count===2?'双向':'单向'));return t;
  }catch(e){s.routes=before;s.relays=previousRelays;if(previousNodes===undefined)delete s.nodes;else s.nodes=previousNodes;s.tunnels=previousTunnels;throw e;}
 }
 function remove(id){const s=getState(),t=get(id);if(bound(t))fail('请先迁移此隧道绑定的业务域名，避免中断生产解析',409);s.routes=s.routes.filter(r=>!t.routeIds.includes(r.id));s.tunnels=s.tunnels.filter(v=>v.id!==id);s.version++;audit('删除隧道',t.name);}
 function merge(input){
  const s=getState(),a=get(input.firstTunnelId),b=get(input.secondTunnelId);
  if(a.id===b.id||a.mode!=='single'||b.mode!=='single'||bound(a)||bound(b))fail('请选择两个未绑定域名的单向隧道',409);
  const x=s.routes.find(r=>r.id===a.routeIds[0]),y=s.routes.find(r=>r.id===b.routeIds[0]);
  if(x.source!==y.target||x.target!==y.source)fail('合并线路的两端节点须互为反向');
  const name=String(input.name||a.name).trim();if(!name||name.length>60)fail('隧道名称应为 1–60 字符');
  const t={id:a.id,name,mode:'bidirectional',routeIds:[x.id,y.id],createdAt:a.createdAt};s.tunnels=s.tunnels.filter(v=>![a.id,b.id].includes(v.id));s.tunnels.push(t);audit('合并双向隧道',name);return t;
 }
 return {get,write,remove,merge};
};
module.exports.normalize=normalize;
module.exports.defaultServerName=(state,input,routeId)=>{
 const tunnel=routeId&&state.tunnels?.find(t=>t.routeIds.includes(routeId));
 const binding=routeId&&(state.domains||[]).find(b=>tunnel&&b.tunnelId===tunnel.id||[b.mainlandRouteId,b.internationalRouteId].includes(routeId));
 return String(input.businessDomain||binding?.domain||[...state.nodes,...state.relays].find(n=>n.id===input.source)?.ingress?.domain||'').trim();
};
