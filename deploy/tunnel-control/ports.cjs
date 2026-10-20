'use strict';
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
module.exports=({getState,getReport})=>{
 function inspect(nodeId,routeId){
  const s=getState(),node=[...s.nodes,...s.relays].find(n=>n.id===nodeId);
  if(!node)fail('请选择已登记的节点');
  const r=getReport(nodeId),own=s.routes.find(v=>v.id===routeId&&v.source===nodeId),used=new Map();
  const add=(port,reason)=>{if(Number.isInteger(port)&&port>0&&port<=65535)used.set(port,reason);};
  if(r.online&&r.ports?.complete)for(const port of r.ports.tcp)if(!(own?.listenPort===port&&r.listeners?.includes(routeId)))add(port,'节点上已有程序监听');
  for(const route of s.routes){if(route.id!==routeId&&route.source===nodeId)add(route.listenPort,'已分配给其他通道');if(route.target===nodeId)add(route.targetPort,'已用作业务服务端口');}
  const carrier=s.relays.find(n=>n.id===nodeId)||node.carrier;
  if(carrier){add(carrier.port,'节点通道协议端口');add(carrier.streamPort||11323,'节点通道协议端口');}
  if(node.ingress)add(node.ingress.port||443,'HTTPS 业务端口');
  add(5092,'管理端口');
  return {used,verified:!!(r.online&&r.ports?.complete),observedAt:r.ports?.observedAt||null};
 }
 function available(nodeId,{routeId,preferred=15081,avoid=[]}={}){
  if(!Number.isInteger(preferred)||preferred<1024||preferred>65535||!Array.isArray(avoid)||avoid.length>4||avoid.some(p=>!Number.isInteger(p)||p<1||p>65535))fail('入口端口应为 1024–65535');
  const result=inspect(nodeId,routeId);for(const p of avoid)result.used.set(p,'当前业务服务端口');
  for(let i=0;i<64512;i++){const port=1024+(preferred-1024+i)%64512;if(!result.used.has(port))return {port,verified:result.verified,observedAt:result.observedAt};}
  fail('此节点没有可用的入口端口',409);
 }
 function validate(nodeId,port,routeId){const info=inspect(nodeId,routeId),reason=info.used.get(port);if(reason)fail(`入口端口 ${port} 不可用：${reason}。请使用“自动选取”或更换端口。`,409);}
 return {available,validate};
};
