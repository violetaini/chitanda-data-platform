'use strict';
(()=>{
 const $=s=>document.querySelector(s),base='/tunnel/api/v1',scopes={'status:read':'读取状态与测活结果','nodes:read':'读取节点','tunnels:read':'读取隧道','nodes:write':'添加、修改和删除节点','tunnels:write':'创建、修改、暂停和删除隧道','checks:write':'发起测活'};
 const titles={'GET /status':'查询中台状态','GET /nodes':'列出节点','GET /nodes/{id}':'查询指定节点','POST /nodes':'创建节点','PATCH /nodes/{id}':'修改节点','DELETE /nodes/{id}':'删除节点','GET /tunnels':'列出隧道及各方向线路','GET /tunnels/{id}':'查询指定隧道','POST /tunnels':'创建隧道','PATCH /tunnels/{id}':'修改、暂停或启用隧道','DELETE /tunnels/{id}':'删除隧道','PUT /tunnels/{id}/http':'更新 URL 请求接入','GET /ports/available':'查询可用端口','GET /routes/{id}/check':'查询测活结果','POST /routes/{id}/test':'发起测活'};
 const esc=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 $('#api-base').textContent=location.origin+base;
 $('#scopes').innerHTML=Object.entries(scopes).map(([scope,label])=>`<div class="scope"><code>${esc(scope)}</code><span>${esc(label)}</span></div>`).join('');
 function type(s){return s.enum?s.enum.join(' / '):s.type==='array'?'array of '+type(s.items||{}):s.type||'object';}
 function field(name,s,required,where){return `<div class="field"><div><code>${esc(name)}</code><small> · ${required?'必填':'可选'}${where?' · '+esc(where):''}</small></div><div>${esc(type(s))}${s.default!==undefined?' · 默认 '+esc(s.default):''}${s.description?' · '+esc(s.description):''}</div></div>`;}
 async function load(){try{
  const r=await fetch('/tunnel/api/management-openapi?format=json',{headers:{Accept:'application/json'},cache:'no-store'});
  if(r.status===401){$('#endpoints').textContent='登录已过期，请返回控制台重新登录。';return;}
  if(!r.ok)throw Error('文档读取失败（'+r.status+'）');const spec=await r.json();
  $('#endpoints').innerHTML=Object.entries(spec.paths).flatMap(([path,methods])=>Object.entries(methods).map(([method,op])=>{
   const verb=method.toUpperCase(),body=op.requestBody?.content?.['application/json']?.schema,parameters=(op.parameters||[]).map(p=>field(p.name,p.schema,p.required,p.in));
   const properties=Object.entries(body?.properties||{}).map(([name,s])=>field(name,s,body.required?.includes(name),'JSON'));
   return `<details><summary><span class="method${verb==='GET'?'':' write'}">${esc(verb)}</span><code class="endpoint-path">${esc(path)}</code></summary><p class="operation-title">${esc(titles[verb+' '+path]||op.summary)}</p><p class="permission">${esc(op.description)}</p>${parameters.length?'<div class="fields">'+parameters.join('')+'</div>':''}${body?'<p>请求体：<code>application/json</code>'+(body.description?' · '+esc(body.description):'')+'</p>'+(properties.length?'<div class="fields">'+properties.join('')+'</div>':'<pre>{}</pre>'):''}${body?.properties?'<details><summary>完整请求体结构</summary><pre>'+esc(JSON.stringify(body,null,2))+'</pre></details>':''}${verb==='PATCH'&&path==='/tunnels/{id}'?'<p>暂停示例：<code>{"enabled":false}</code>；启用改为 <code>true</code>。</p>':''}${path.endsWith('/test')?'<p>提交后返回 202；使用同一条线路 ID 查询 <code>GET /routes/{id}/check</code> 获取结果。</p>':''}</details>`;
  })).join('');
 }catch(e){$('#endpoints').textContent=e.message;}}
 let pending;
 function clear(){pending?.abort();pending=undefined;$('#api-key').value='';$('#query-result').textContent='';$('#query-result').hidden=true;$('#query-status').textContent='密钥已清除';$('#query-status').dataset.error='false';$('#send-query').disabled=false;}
 $('#clear-key').addEventListener('click',clear);window.addEventListener('pagehide',clear);window.addEventListener('pageshow',e=>{if(e.persisted)clear();});
 $('#query-form').addEventListener('submit',async e=>{
  e.preventDefault();const key=$('#api-key').value.trim(),path=$('#query-path').value;
  if(!/^ctm_[a-f0-9]{16}_[a-f0-9]{64}$/.test(key)){$('#query-status').textContent='请填写系统设置创建的管理 API 密钥（ctm_ 开头）。';$('#query-status').dataset.error='true';return;}
  if(!['/status','/nodes','/tunnels'].includes(path))return;
  const controller=new AbortController();pending?.abort();pending=controller;$('#send-query').disabled=true;$('#query-status').textContent='正在查询…';$('#query-status').dataset.error='false';$('#query-result').textContent='';$('#query-result').hidden=true;
  const timeout=setTimeout(()=>controller.abort(),15000);
  try{
   const r=await fetch(base+path,{method:'GET',headers:{Authorization:'Bearer '+key,Accept:'application/json'},credentials:'omit',cache:'no-store',signal:controller.signal,redirect:'error'}),data=await r.json();
   if(pending!==controller)return;
   $('#query-status').textContent=r.ok?'HTTP '+r.status+' · 查询成功':'HTTP '+r.status+' · '+(data.error||'查询失败');$('#query-status').dataset.error=String(!r.ok);
   const text=JSON.stringify(data,null,2);$('#query-result').textContent=text.length>60000?text.slice(0,60000)+'\n…结果较长，请通过 API 获取完整数据。':text;$('#query-result').hidden=false;
  }catch(error){if(pending===controller){$('#query-status').textContent=error.name==='AbortError'?'查询超时，请重试。':'请求未完成，请检查网络或来源 IP 限制。';$('#query-status').dataset.error='true';}}
  finally{clearTimeout(timeout);if(pending===controller){pending=undefined;$('#send-query').disabled=false;}}
 });load();
})();
