'use strict';
const crypto=require('node:crypto'),net=require('node:net');
const fail=(message,status=400)=>{throw Object.assign(Error(message),{status});};
function object(input,keys){if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!keys.includes(k)))fail('请求字段不正确');}
function address(value){
 if(typeof value!=='string'||value!==value.trim()||value.length>64||value.includes('%'))fail('请填写有效的 IP 或 CIDR 网段');
 const [ip,bits,...extra]=value.split('/'),family=net.isIP(ip);if(!family||extra.length||bits!==undefined&&(!/^\d{1,3}$/.test(bits)||Number(bits)>(family===4?32:128)))fail('请填写有效的 IP 或 CIDR 网段');
 const normalized=family===6?new URL('http://['+ip+']/').hostname.slice(1,-1):ip;
 if(bits!==undefined&&Number(bits)===0)fail('不能将全部 IP 加入白名单');
 const block=new net.BlockList();if(bits!==undefined)block.addSubnet(normalized,Number(bits),family===4?'ipv4':'ipv6');
 return normalized+(bits===undefined||Number(bits)===(family===4?32:128)?'':'/'+Number(bits));
}
function hostname(value){if(typeof value!=='string'||value.length>253||value!==value.trim())fail('请填写有效的服务域名');const v=value.toLowerCase();if(!v.includes('.')||net.isIP(v)||!v.split('.').every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p)))fail('请填写有效的服务域名');return v;}
module.exports=function({getState,getReport=()=>({}),audit}){
 const state=()=>getState(),all=()=>state().downloadServices||[],find=id=>all().find(s=>s.id===id)||fail('下载服务不存在',404),nodes=()=>[...state().nodes,...state().relays];
 function publicService(s){const n=nodes().find(n=>n.id===s.nodeId),r=getReport(s.nodeId),d=r.downloadAccess;return {...s,nodeName:n?.name||s.nodeId,nodeHost:n?.host||'',online:!!r.online,appliedRevision:d?.revision||0,status:!r.online?'offline':!d?.supported?'unsupported':d.revision!==s.revision?'pending':!s.enabled?'paused':d.ready?'applied':'unavailable',lastSeen:r.seen?new Date(r.seen).toISOString():null};}
 function changed(s,action,detail){s.revision++;s.updatedAt=new Date().toISOString();audit(action,s.name+' · '+detail);return publicService(s);}
 function create(input){
  object(input,['name','domain','nodeId']);const name=typeof input.name==='string'?input.name.trim():'';if(!name||name.length>60)fail('服务名称应为 1–60 个字符');const domain=hostname(input.domain),node=nodes().find(n=>n.id===input.nodeId);if(!node)fail('请选择有效节点');
  if(all().length>=16)fail('最多添加 16 个下载服务');if(all().some(s=>s.domain===domain||s.nodeId===node.id))fail('该域名或节点已有下载服务',409);
  const s={id:'download-'+crypto.randomBytes(6).toString('hex'),name,domain,nodeId:node.id,enabled:true,revision:1,entries:[],createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};(state().downloadServices||=[]).push(s);audit('添加下载服务',s.name+' · '+domain);return publicService(s);
 }
 function update(id,input){object(input,['name','enabled']);const s=find(id);if(input.name!==undefined){if(typeof input.name!=='string'||!input.name.trim()||input.name.trim().length>60)fail('服务名称应为 1–60 个字符');}if(input.enabled!==undefined&&typeof input.enabled!=='boolean')fail('启用状态不正确');if(!Object.keys(input).length)fail('请填写需要修改的项目');if(input.name!==undefined)s.name=input.name.trim();if(input.enabled!==undefined)s.enabled=input.enabled;return changed(s,'更新下载服务',s.enabled?'仅白名单可用':'已暂停');}
 function add(id,input){object(input,['address','note']);const s=find(id),ip=address(input.address),note=input.note===undefined?'':input.note;if(typeof note!=='string'||note.length>120)fail('备注最多 120 个字符');if(s.entries.length>=256)fail('每个服务最多 256 条白名单');if(s.entries.some(e=>e.address===ip))fail('该地址已在白名单中',409);s.entries.push({id:crypto.randomBytes(8).toString('hex'),address:ip,note:note.trim(),createdAt:new Date().toISOString()});return changed(s,'添加下载白名单',ip);}
 function remove(id,entryId){const s=find(id),e=s.entries.find(e=>e.id===entryId);if(!e)fail('白名单条目不存在',404);s.entries=s.entries.filter(e=>e!==undefined&&e.id!==entryId);return changed(s,'移除下载白名单',e.address);}
 function drop(id,input){object(input,[]);const s=find(id);state().downloadServices=all().filter(x=>x.id!==id);audit('移除下载服务',s.name+' · 节点恢复后会停止此域名入口');return {ok:true};}
 function forNode(id){const s=all().find(s=>s.nodeId===id);return s?{id:s.id,domain:s.domain,enabled:s.enabled,revision:s.revision,allowed:s.entries.map(e=>e.address)}:null;}
 return {list:()=>all().map(publicService),create,update,add,remove,drop,forNode};
};
module.exports.address=address;module.exports.hostname=hostname;
