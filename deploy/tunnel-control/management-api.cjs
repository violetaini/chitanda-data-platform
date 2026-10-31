'use strict';
// Only these explicitly mapped resources can use API keys. Browser/admin endpoints
// (credentials, certificates, DNS credentials, enrollment and key issuance) stay separate.
const routes=[
 ['GET','/status','status:read','status'],['GET','/nodes','nodes:read','nodes'],['GET','/nodes/{id}','nodes:read','node'],
 ['POST','/nodes','nodes:write','panel'],['PATCH','/nodes/{id}','nodes:write','panel'],['DELETE','/nodes/{id}','nodes:write','panel'],
 ['GET','/tunnels','tunnels:read','tunnels'],['GET','/tunnels/{id}','tunnels:read','tunnel'],
 ['POST','/tunnels','tunnels:write','panel'],['PATCH','/tunnels/{id}','tunnels:write','panel'],['DELETE','/tunnels/{id}','tunnels:write','panel'],
 ['PUT','/tunnels/{id}/http','tunnels:write','panel'],['GET','/ports/available','nodes:read','panel'],
 ['GET','/routes/{id}/check','status:read','check'],['POST','/routes/{id}/test','checks:write','panel']
].map(([method,path,scope,action])=>({method,path,scope,action,re:new RegExp('^'+path.replace('{id}','([a-zA-Z0-9-]{1,80})')+'$')}));
function match(path,method){for(const r of routes){const m=path.match(r.re);if(m&&method===r.method)return {...r,id:m[1],panel:path};}return null;}
const fail=()=>{throw Object.assign(Error('资源不存在'),{status:404});};
function view(route,s){
 const nodes=s.nodes.concat(s.relays),tunnels=s.tunnels.map(t=>({...t,routes:t.routeIds.map(id=>s.routes.find(r=>r.id===id)).filter(Boolean)}));
 if(route.action==='status')return {version:s.control.version,revision:s.version,now:s.now,nodes:{total:nodes.length,online:nodes.filter(n=>n.online).length},tunnels:{total:tunnels.length,enabled:tunnels.filter(t=>t.routes.some(r=>r.enabled)).length}};
 if(route.action==='nodes')return {items:nodes,revision:s.version};
 if(route.action==='node')return nodes.find(n=>n.id===route.id)||fail();
 if(route.action==='tunnels')return {items:tunnels,revision:s.version};
 if(route.action==='tunnel')return tunnels.find(t=>t.id===route.id)||fail();
 if(route.action==='check'){const r=s.routes.find(v=>v.id===route.id)||fail();return {routeId:r.id,enabled:r.enabled,configPending:r.configPending,ready:!!(r.sourceOnline&&r.targetOnline&&r.relayOnline),listenError:r.listenError,result:r.test||null};}
}
function schema(){
 const string={type:'string'},integer={type:'integer'},bool={type:'boolean'},node={type:'object',required:['name','purpose'],properties:{name:{type:'string',maxLength:60},purpose:{type:'string',enum:['mainland','international','relay']},port:{...integer,default:443},serverName:string}},tunnel={type:'object',required:['name','source','target','listenPort','targetPort'],properties:{name:string,source:string,target:string,mode:{type:'string',enum:['single','bidirectional']},relayId:string,relayIds:{type:'array',items:string,maxItems:8},transport:{type:'string',enum:['h2','h3','stream']},backupPaths:{type:'array',maxItems:8,description:'Ordered alternate paths for the same logical route; reverse directions are generated automatically. Requires source node 2.14.0 or newer.',items:{type:'object',additionalProperties:false,required:['relayIds'],properties:{id:string,name:string,direct:bool,relayIds:{type:'array',items:string,maxItems:8},transport:{type:'string',enum:['h2','h3','stream']},serverName:string}}},listenPort:integer,targetPort:integer,reverseListenPort:integer,reverseTargetPort:integer,serverName:string,enabled:bool}},target={type:'object',required:['baseURL'],properties:{baseURL:{type:'string',format:'uri'},connectAddress:string}},policy={type:'object',required:['enabled','directions'],properties:{enabled:bool,directions:{type:'array',items:{type:'object',required:['routeId','targets'],properties:{routeId:string,targets:{type:'array',items:target,maxItems:16}}}}}};
 const paths={};for(const r of routes){const op={summary:r.method+' '+r.path,description:'所需权限：'+r.scope,security:[{managementKey:[]}],responses:{200:{description:'成功；创建可能返回 201，测活返回 202'},400:{description:'参数不正确'},401:{description:'密钥失效'},403:{description:'来源 IP 或权限不允许'},409:{description:'资源冲突或受关联资源保护'},429:{description:'请求限流'}}};
  if(r.method==='POST'&&r.path==='/nodes'||r.method==='POST'&&r.path==='/tunnels')op.responses[201]={description:'已创建'};
  if(r.path.endsWith('/test'))op.responses[202]={description:'测试已提交，查询 check 获取结果'};
  if(r.path.includes('{id}'))op.parameters=[{in:'path',name:'id',required:true,schema:{type:'string'}}];
  if(!['GET','HEAD'].includes(r.method)){
   let body={type:'object',additionalProperties:false};
   if(r.path==='/nodes')body=node;
   if(r.path==='/nodes/{id}'&&r.method==='PATCH')body={type:'object',properties:{name:string,certificateRoot:string}};
   if(r.path==='/nodes/{id}'&&r.method==='DELETE')body={type:'object',properties:{cascade:{...bool,default:false}},description:'cascade=true 删除关联隧道时还需要 tunnels:write 权限；已绑定域名需先处理。'};
   if(r.path==='/tunnels')body=tunnel;
   if(r.path==='/tunnels/{id}'&&r.method==='PATCH')body={...tunnel,required:[],description:'仅暂停/启用时只传 enabled，其余字段沿用当前值。'};
   if(r.path.endsWith('/http'))body=policy;
   op.requestBody={required:true,content:{'application/json':{schema:body}}};
  }
  if(r.path==='/ports/available')op.parameters=[{in:'query',name:'nodeId',required:true,schema:{type:'string'}},{in:'query',name:'preferred',schema:{type:'integer',default:15081}},{in:'query',name:'routeId',schema:{type:'string'}},{in:'query',name:'avoid',schema:{type:'array',items:{type:'integer'}},explode:true}];
  (paths[r.path]||={})[r.method.toLowerCase()]=op;
 }
 return {openapi:'3.1.0',info:{title:'Chitanda 中台管理 API',version:'1.0.0',description:'独立管理密钥，与业务隧道令牌分开；沿用管理来源 IP 限制。'},servers:[{url:'/tunnel/api/v1'}],components:{securitySchemes:{managementKey:{type:'http',scheme:'bearer',bearerFormat:'ctm_id_secret'}}},paths};
}
module.exports={match,view,schema};
