'use strict';
let nodeInstallation=null,guideBindingId='',guideRouteId='',guideTunnelId='',guideTargetURL='',guideTransferKind='json';
function codeBox(text,label,copy=true){return `<div class="onboarding-code"><pre>${esc(text)}</pre>${copy?`<button class="icon-button" data-copy-example aria-label="复制${esc(label)}" title="复制${esc(label)}">${icon('copy')}</button>`:''}</div>`;}
let installationSource='github',installationLoading=false,installationEpoch=0,installationActionChoice='';
function paintNodeInstallation(){
 const r=nodeInstallation;if(!r)return;const compatOpen=!!$('#node-install-compat')?.open;const verb=r.action==='uninstall'?'卸载':'安装';
 $('#node-install-title').textContent=r.action==='install'&&r.installed?'重新安装节点':verb+'节点';
 $('#enroll-installation').innerHTML=`<p class="muted">${esc(r.name)} · ${r.online?'在线':r.installed?'离线 · 无法确认本机安装状态':'等待首次上线确认'}</p><div class="installation-source-tabs" role="group" aria-label="脚本来源">${[['github','GitHub'],['origin','源站']].map(([key,label])=>`<button class="button ${installationSource===key?'primary':'secondary'}" data-install-source="${key}" aria-pressed="${installationSource===key}">${label}</button>`).join('')}</div>${r.available?'':`<p class="form-error">${esc(r.error)}</p>`}<pre id="node-install-command">${esc(r.commands[installationSource])}</pre><p class="form-note">${installationSource==='github'?'GitHub 下载公开启动脚本':'源站下载公开启动脚本'}；需要 curl，其余依赖自动安装。</p><details id="node-install-compat" ${compatOpen?'open':''}><summary>缺少 curl 时使用兼容指令</summary><pre id="node-install-compat-command">${esc(r.compatCommands[installationSource])}</pre><button class="button secondary" data-copy-compat ${r.available?'':'disabled'}>复制兼容${verb}指令</button></details><p class="form-note">${r.action==='uninstall'?'在目标服务器的 root 终端执行。停止服务并移除程序，默认保留配置、缓存和证书；不删除面板节点。':`在目标服务器的 root 终端执行。有效至 ${time(r.expiresAt,true)}；${r.installed?'保留原节点身份与已有配置，程序仍在时可覆盖修复。':'自动准备 Linux 依赖，支持 systemd / OpenRC / runit / SysV，安装后启用自动更新。'}`}</p><div class="dialog-actions">${r.installed?`<button class="text-button" data-install-action="${r.action==='uninstall'?'install':'uninstall'}">${r.action==='uninstall'?'重新安装':'查看卸载指令'}</button>`:''}${r.action==='uninstall'?'':`<button class="button secondary" data-renew-install="${esc(r.nodeId)}">重新生成</button>`}<button class="button primary" data-copy-install ${r.available?'':'disabled'}>${icon('copy')}复制${verb}指令</button></div>`;
}
async function openNodeInstallation(id,action=''){
 if(installationLoading)return;installationLoading=true;
 const epoch=installationEpoch;try{const result=await api('installations',{method:'POST',body:JSON.stringify({id,...(action?{action}:{})})});if(epoch!==installationEpoch)return;nodeInstallation=result;installationActionChoice=action;paintNodeInstallation();if(!$('#enroll-dialog').open)$('#enroll-dialog').showModal();}finally{installationLoading=false;}
}
async function syncNodeInstallation(){
 if(!nodeInstallation||!$('#enroll-dialog').open||installationLoading)return;
 const n=allNodes().find(n=>n.id===nodeInstallation.nodeId);
 if(!n){$('#enroll-dialog').close();return;}
 if(!!n.installed!==nodeInstallation.installed||!!n.online!==nodeInstallation.online)await openNodeInstallation(n.id,installationActionChoice);
}
function guideShellQuote(value){return "'"+String(value).replace(/'/g,"'\\''")+"'";}
function guideRequestURL(baseURL){
 try{const base=new URL(baseURL),status=new URL('/api/sync/status',base),prefix=base.pathname.replace(/\/$/,'');return status.pathname===prefix||status.pathname.startsWith(prefix+'/')?status.href:base.href;}catch{return baseURL;}
}
function onboardingGuide(){
 const ts=tunnelList(),allBindings=data.dns?.bindings||[],selected=ts.find(t=>t.id===guideTunnelId)||ts.find(t=>t.id===allBindings.find(b=>b.id===guideBindingId)?.tunnelId)||ts.find(t=>t.id===allBindings[0]?.tunnelId)||ts[0],bindings=allBindings.filter(b=>b.tunnelId===selected?.id),binding=bindings.find(b=>b.id===guideBindingId)||bindings[0],rs=selected?selected.routeIds.map(id=>data.routes.find(r=>r.id===id)).filter(Boolean):[];
 const direction=rs.find(r=>r.id===guideRouteId)||rs[0],source=allNodes().find(n=>n.id===direction?.source),url='https://'+(binding?.domain||source?.ingress?.domain||'你的业务接入域名'),access=data.httpAccess?.[selected?.id],policy=access?.directions?.find(v=>v.routeId===direction?.id),targets=policy?.targets||[],target=targets.find(v=>v.baseURL===guideTargetURL)||targets[0],baseURL=target?.baseURL||'https://目标业务域名/api/sync/',requestURL=guideRequestURL(baseURL);
 let targetOrigin='https://目标业务域名';try{targetOrigin=new URL(baseURL).origin;}catch{}
 const auth=`  -H "Authorization: Bearer \${CHITANDA_TUNNEL_TOKEN}"`;
 const callTarget=guideTransferKind==='get'?requestURL:baseURL;
 const lines=["CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'",'curl --fail-with-body --connect-timeout 5 --max-time 30',auth,'  -H '+guideShellQuote('X-Target-URL: '+callTarget)];
 if(guideTransferKind==='json')lines.push("  -H 'Content-Type: application/json'",'  --data-binary '+guideShellQuote('{"message":"hello","value":123}'));
 if(guideTransferKind==='file')lines.push("  -H 'Content-Type: application/octet-stream'",'  --data-binary @./example.bin');
 if(guideTransferKind==='get')lines.push('  --output ./response.dat');
 const request=lines[0]+'\n'+lines.slice(1).concat('  '+guideShellQuote(url+'/')).join(' \\\n');
 const env=`CHITANDA_SYNC_PEERS=${url}
CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'
CHITANDA_SYNC_TARGET=${targetOrigin}`;
 const pending=rs.some(r=>r.configPending),enabled=!!access?.enabled;
 return `<div class="onboarding-guide"><section class="panel onboarding-intro"><span class="section-kicker">QUICK START</span><h2>通过隧道收发数据</h2><p>把数据放在 HTTPS 请求里发出，对方业务处理后，结果沿隧道返回给你。</p>
 ${ts.length>1?`<label>选择隧道<select id="guide-tunnel">${ts.map(t=>`<option value="${esc(t.id)}" ${t.id===selected?.id?'selected':''}>${esc(t.name)}</option>`).join('')}</select></label>`:''}
 ${bindings.length>1?`<label>入口域名<select id="guide-binding" aria-label="教程业务域名">${bindings.map(b=>`<option value="${esc(b.id)}" ${b.id===binding.id?'selected':''}>${esc(b.domain)}</option>`).join('')}</select></label>`:''}
 ${rs.length>1?`<label>请求方向<select id="guide-route">${rs.map(r=>`<option value="${esc(r.id)}" ${direction?.id===r.id?'selected':''}>${esc(nodeName(r.source))} → ${esc(nodeName(r.target))}</option>`).join('')}</select></label>`:''}
 ${targets.length>1?`<label>目标业务<select id="guide-target">${targets.map(t=>`<option value="${esc(t.baseURL)}" ${t.baseURL===baseURL?'selected':''}>${esc(t.baseURL)}</option>`).join('')}</select></label>`:''}
 <div class="guide-addresses"><div><small>隧道入口 · 请求发到这里</small>${codeBox(url,'隧道入口')}</div><div><small>目标业务 · 数据交给这里</small>${codeBox(baseURL,'目标业务地址')}</div></div>
 ${!binding?'<p class="form-note">尚未绑定业务域名；请先准备可用的 HTTPS 入口。</p>':''}
 <p class="form-note" data-guide-access-status>${!selected?'请先创建隧道，下方仅为格式示例。':rs.length&&rs.every(r=>!r.enabled)?'当前隧道已暂停。':!enabled?'尚未启用 URL 请求接入，请先完成第 1 步。':!targets.length?'当前方向尚未设置目标业务。':pending?'正在等待节点应用配置。':'当前方向已启用 URL 请求接入。'}</p></section>
 <section class="panel guide-transfer"><h2>照这三步使用</h2><ol class="onboarding-steps">
 <li><strong>面板填好目标，复制令牌</strong><p>在隧道详情的“URL 请求接入”启用开关，填对方业务的 HTTPS 地址并保存，再复制本隧道令牌。</p>${selected?`<button class="text-button" data-guide-config="${esc(selected.id)}">打开当前隧道 ${icon('arrow')}</button>`:'<button class="text-button" data-view="tunnels">打开数据通道</button>'}</li>
 <li><strong>在发送方执行下面的请求</strong><p>替换令牌，把 <code>X-Target-URL</code> 改成对方业务真实的接收接口。下面演示数据怎么放进请求；接口路径和数据格式按你的业务填写。</p>
 <label>我要做什么<select id="guide-transfer-kind"><option value="json" ${guideTransferKind==='json'?'selected':''}>发送 JSON 数据</option><option value="file" ${guideTransferKind==='file'?'selected':''}>上传文件内容</option><option value="get" ${guideTransferKind==='get'?'selected':''}>读取数据或下载文件</option></select></label>
 ${codeBox(request,'HTTPS 请求示例')}
 <p class="guide-payload-note">${guideTransferKind==='json'?'<code>--data-binary</code> 后面的 JSON 就是实际发送的数据，curl 会以 POST 发出；把它换成你的内容。':guideTransferKind==='file'?'<code>@./example.bin</code> 表示读取发送方的本地文件，以 POST 把文件内容发给对方。替换成你的文件路径；接收接口需支持二进制文件内容。':'此示例使用 GET；对方返回的内容保存到发送方的 <code>./response.dat</code>，可改成自己的保存路径。'}</p></li>
 <li><strong>对方接收，结果原路返回</strong><p>目标业务接口收到同一份 JSON 或文件内容，由它负责保存、入库或处理。JSON 和上传示例会把对方返回的结果直接显示在终端；读取示例则保存到文件。</p><p>隧道负责把请求和回复送到两端。对方必须已有接收接口，隧道不会自动创建接口或替业务保存文件。反方向发送时，切换上方“请求方向”即可查看对应示例。</p></li></ol></section>
 <section class="panel guide-more"><details><summary>Chitanda 怎么接入</summary><p>Chitanda 已有数据同步逻辑。在业务后台的环境配置填写三项，再重新加载后台；之后事件、设置和文件分片由它自动发送，不用手工执行每次 curl。</p>${codeBox(env,'业务环境配置')}<p><code>SYNC_PEERS</code> 是隧道入口，<code>TUNNEL_TOKEN</code> 是本隧道令牌，<code>SYNC_TARGET</code> 是对端原网站地址。重置令牌后，业务后台也要更新。</p></details>
 <details><summary>接入没成功时看这里</summary><p>401：检查令牌；403：检查入口权限和目标设置；404：检查业务接口路径；502 或超时：检查节点、回源地址及证书。</p><p>入口证书在系统设置管理，节点管理确认应用。目标域名经过 CDN 或需要指定对端源站时，在“URL 请求接入 → 固定回源地址”填写公开 IP:端口。</p><p>同一 IP 有多个网站时，目标 URL 的域名决定交给哪个网站。业务另有 Authorization 时，用 <code>X-Target-Authorization</code> 携带。大文件按业务接口分片，每次请求不超过 16 MiB。</p></details>
 <details><summary>新节点的安装与卸载</summary><p>节点管理添加节点后，选择 GitHub 或源站并复制安装指令。离线可重新安装，在线可查看卸载指令；卸载默认保留配置和证书。自动更新策略在系统设置调整。</p><button class="button secondary" data-view="nodes">前往节点管理 ${icon('arrow')}</button></details></section></div>`;
}
document.addEventListener('change',event=>{if(event.target.id==='guide-transfer-kind'){guideTransferKind=event.target.value;render();}if(event.target.id==='guide-tunnel'){guideTunnelId=event.target.value;guideBindingId='';guideRouteId='';guideTargetURL='';render();}if(event.target.id==='guide-route'){guideRouteId=event.target.value;guideTargetURL='';render();}if(event.target.id==='guide-target'){guideTargetURL=event.target.value;render();}if(event.target.id==='guide-binding'){guideBindingId=event.target.value;render();}});
document.addEventListener('click',async event=>{
 const b=event.target.closest('[data-copy-example],[data-copy-install],[data-copy-compat],[data-renew-install],[data-install-action],[data-install-source],[data-guide-tunnel],[data-guide-config]');if(!b)return;
 try{
  if(b.dataset.guideConfig){view='tunnels';expandedTunnels.add(b.dataset.guideConfig);render();document.querySelector(`[data-tunnel-card="${CSS.escape(b.dataset.guideConfig)}"]`)?.scrollIntoView({block:'start'});return;}
  if(b.dataset.guideTunnel){guideTunnelId=b.dataset.guideTunnel;guideRouteId='';guideTargetURL='';guideBindingId=data.dns?.bindings.find(v=>v.tunnelId===b.dataset.guideTunnel)?.id||'';view='guide';render();return;}
  if(b.dataset.installSource){installationSource=b.dataset.installSource;paintNodeInstallation();return;}
  if(b.dataset.installAction){await openNodeInstallation(nodeInstallation.nodeId,b.dataset.installAction);return;}
  if(b.dataset.renewInstall){await openNodeInstallation(b.dataset.renewInstall,installationActionChoice);return;}
  let text;if(b.hasAttribute('data-copy-example'))text=b.closest('.onboarding-code').querySelector('pre').textContent;
  else{if(!nodeInstallation||nodeInstallation.action==='install'&&Date.now()>=Date.parse(nodeInstallation.expiresAt))throw Error('安装命令已过期，请重新生成');text=(b.hasAttribute('data-copy-compat')?nodeInstallation.compatCommands:nodeInstallation.commands)[installationSource];}
  await navigator.clipboard.writeText(text);toast('已复制');
 }catch(error){toast(error.message||'复制失败，请手动选择命令',true);}
});
$('#enroll-dialog').addEventListener('close',()=>{installationEpoch++;installationActionChoice='';nodeInstallation=null;$('#enroll-installation').replaceChildren();});
