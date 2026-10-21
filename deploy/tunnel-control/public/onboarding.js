'use strict';
let nodeInstallation=null,guideBindingId='',guideRouteId='',guideTunnelId='',guideTargetURL='';
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
 const request=`CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'
curl --fail-with-body --connect-timeout 5 --max-time 30 \\
  -H "Authorization: Bearer \${CHITANDA_TUNNEL_TOKEN}" \\
  -H ${guideShellQuote('X-Target-URL: '+requestURL)} \\
  ${guideShellQuote(url+'/')}`;
 const env=`CHITANDA_SYNC_PEERS=${url}
CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'
CHITANDA_SYNC_TARGET=${targetOrigin}`;
 const pending=rs.some(r=>r.configPending),enabled=!!access?.enabled;
 return `<div class="onboarding-guide"><section class="panel onboarding-intro"><span class="section-kicker">HTTPS URL ACCESS</span><h2>用 HTTPS 请求指定目标业务</h2><p>请求先发到隧道入口。令牌告诉入口“走哪条隧道”，请求头 <code>X-Target-URL</code> 告诉出口“交给哪个网站的哪个接口”。</p>
 ${!selected?'<p class="onboarding-note">请先在“数据通道”创建隧道；下方为格式示例，不代表已经完成接入。</p>':''}
 ${ts.length>1?`<label>选择隧道<select id="guide-tunnel">${ts.map(t=>`<option value="${esc(t.id)}" ${t.id===selected?.id?'selected':''}>${esc(t.name)}</option>`).join('')}</select></label>`:''}
 ${bindings.length>1?`<label>选择入口域名<select id="guide-binding" aria-label="教程业务域名">${bindings.map(b=>`<option value="${esc(b.id)}" ${b.id===binding.id?'selected':''}>${esc(b.domain)}</option>`).join('')}</select></label>`:''}
 ${rs.length>1?`<label>请求方向<select id="guide-route">${rs.map(r=>`<option value="${esc(r.id)}" ${direction?.id===r.id?'selected':''}>${esc(nodeName(r.source))} → ${esc(nodeName(r.target))}</option>`).join('')}</select></label>`:''}
 ${targets.length>1?`<label>目标业务<select id="guide-target">${targets.map(t=>`<option value="${esc(t.baseURL)}" ${t.baseURL===baseURL?'selected':''}>${esc(t.baseURL)}</option>`).join('')}</select></label>`:''}
 <div class="guide-addresses"><div><small>① 请求发到这里 · 隧道入口</small>${codeBox(url,'隧道入口')}</div><div><small>② 最终交给这里 · 目标业务</small>${codeBox(requestURL,'目标业务地址')}<p class="form-note">允许范围：${target?esc(baseURL):'尚未配置，当前为格式示例'}</p></div></div>
 <p class="form-note">${binding?(binding.status==='published'?'入口域名解析已发布':'入口解析尚未发布，请先在隧道详情预览并发布'):'尚未绑定业务域名；可使用源节点已有的 HTTPS 接入地址。'} 面板域名只用于管理，不能作为业务入口。</p>
 <p class="onboarding-note" data-guide-access-status>${!selected?'尚未选择隧道':rs.length&&rs.every(r=>!r.enabled)?'当前隧道已暂停，请先启用隧道。':!enabled?'当前隧道尚未启用 URL 请求接入，请先按下方步骤配置。':!targets.length?'当前方向尚未配置允许的业务目标。':pending?'URL 请求接入已启用，正在等待节点应用配置。':'URL 请求接入已启用；请结合节点状态和实际接口请求确认业务可用。'}</p>
 <p class="form-note">教程根据当前隧道、方向和目标生成。切换后地址和示例一起更新；仅切换教程选项不会修改隧道。</p></section>
 <div class="onboarding-columns"><section class="panel"><span class="section-kicker">PANEL SETUP</span><h2>先在面板配置</h2><ol class="onboarding-steps">
 <li><strong>准备 HTTPS 入口</strong><p>在“系统设置 → SSL 证书”添加根域名，选择自动申请、DNS 面板同步或自行上传。三种方式均使用泛域名证书；在节点管理中为入口节点选择对应证书根域名，并确认已应用。</p></li>
 <li><strong>设置隧道与入口域名</strong><p>在“数据通道”选择节点路径、方向及 H2 / H3 / Stream。需要域名时，在隧道的域名设置中绑定并发布解析。每条隧道有独立令牌；同一 HTTPS 入口可以承接多条隧道。</p></li>
 <li><strong>填写允许访问的业务范围</strong><p>展开对应隧道的详情，打开“URL 请求接入”，启用“请求头指定业务地址”。为每个方向填写目标业务原有的 HTTPS 地址范围，例如 <code>https://业务域名/api/sync/</code>。多个网站可分别添加，保存后自动下发节点。</p></li>
 <li><strong>需要时指定实际源站 IP</strong><p>在目标业务下面展开“固定回源地址（可选）”。通常留空，由出口解析业务域名；若域名经过 CDN、地区解析，或会指回隧道入口，可填写真正源站的公开 <code>IP:端口</code>。每个方向分别设置。</p><p>即使一个 IP 的 443 端口有多个网站，出口仍使用目标 URL 的域名作为 Host 和 TLS SNI，交给对应网站。业务源站沿用原有网站配置，无需另建隧道专用映射。</p></li>
 <li><strong>查看隧道令牌</strong><p>展开对应隧道的详情，查看或复制“隧道令牌”。创建时自动生成，双向共用。重置后自动下发节点，调用程序也要改用新令牌；离线节点恢复联系后应用最新配置。</p></li></ol>
 ${selected?`<button class="button secondary" data-guide-config="${esc(selected.id)}">前往当前隧道 ${icon('arrow')}</button>`:'<button class="button secondary" data-view="tunnels">前往数据通道</button>'}</section>
 <section class="panel"><span class="section-kicker">REQUEST EXAMPLE</span><h2>调用程序怎么填写</h2><ol class="onboarding-steps">
 <li><strong>先在业务服务器验证</strong><p>将占位符替换为当前隧道令牌，再执行下方命令。入口地址、目标地址来自上方选择。示例使用 GET；普通业务请改成自己实际存在的接口，不会自动创建 <code>/status</code> 接口。</p>${codeBox(request,'HTTPS 请求示例')}</li>
 <li><strong>三个位置各管一件事</strong><p>curl 最后一行是隧道入口；<code>Authorization: Bearer</code> 携带隧道令牌；<code>X-Target-URL</code> 填目标业务的完整 HTTPS 地址，包含接口路径和查询参数。</p></li>
 <li><strong>发送实际业务数据</strong><p>按原接口填写请求方法、Content-Type 和请求体，例如 POST JSON 或文件分片。出口保留方法、查询参数和载体；业务程序负责数据格式与同步逻辑。</p></li>
 <li><strong>业务独立鉴权</strong><p>默认把当前 Bearer 继续交给目标业务。目标业务若要求另一项 Authorization，可用 <code>X-Target-Authorization</code> 携带；其他 API Key 使用原接口要求的请求头。</p></li></ol><div class="onboarding-note">URL 模式使用目标 HTTPS 地址，不再填写旧的目标服务端口。原始 TCP 业务按入口端口接入，不发送 X-Target-URL；H2 / H3 / Stream 是节点之间的协议。</div></section></div>
 <section class="panel"><span class="section-kicker">CHITANDA EXAMPLE</span><h2>Chitanda 怎么接入</h2><p>在实际运行 Chitanda 后台的环境配置中填写下面三项，随后按业务部署方式重启或重新加载后台。已有配置先核对，不要直接用占位符覆盖。</p>${codeBox(env,'业务环境配置')}
 <div class="guide-troubleshooting"><div><strong>CHITANDA_SYNC_PEERS</strong><p>隧道的 HTTPS 入口地址。两端已配置地区解析时可使用同一入口域名；否则分别使用各自可达的入口地址。</p></div><div><strong>CHITANDA_TUNNEL_TOKEN</strong><p>当前隧道的一个令牌。无需再新填两套同步和入口凭据；重置令牌后，所有使用它的业务端也要更新。</p></div><div><strong>CHITANDA_SYNC_TARGET</strong><p>对端 Chitanda 原有网站地址，仅填写站点地址。后台自动拼接原同步接口路径，生成 X-Target-URL；无需手动改每次请求。</p></div><div><strong>国内、国际使用同一网站域名时</strong><p>可在两个方向的“固定回源地址”分别填写对端实际源站 IP。URL 仍使用原业务域名，TLS 和网站识别保持一致。</p></div></div><p class="form-note">以上变量需要业务程序支持请求头接入；普通 HTTP 服务按自己的接口发送请求即可。隧道测活成功只代表通道可用，完整同步还需验证真实业务接口。</p></section>
 <section class="panel"><span class="section-kicker">TROUBLESHOOTING</span><h2>按返回结果排查</h2><div class="guide-troubleshooting"><div><strong>400</strong><p>检查 X-Target-URL 是否为完整合法的 HTTPS 地址。</p></div><div><strong>401</strong><p>检查当前隧道令牌、节点是否应用最新配置，以及业务本身鉴权。</p></div><div><strong>403</strong><p>检查入口来源授权、目标域名和路径是否在当前方向允许范围内，以及业务自身权限。</p></div><div><strong>404</strong><p>检查目标网站与接口路径；普通服务不一定提供状态接口。</p></div><div><strong>502 / 超时</strong><p>检查节点通道、出口到源站网络、DNS、固定回源地址和业务证书。</p></div><div><strong>测活通过但业务失败</strong><p>再用实际业务 URL 调用，核对 HTTP 返回、鉴权和载体；测活不会代替业务接口验证。</p></div></div></section>
 <section class="panel"><span class="section-kicker">NODE LIFECYCLE</span><h2>新节点的安装与卸载</h2><ol class="onboarding-steps"><li>在节点管理添加名称与用途，系统分配独立身份。</li><li>选择 GitHub 或源站，复制安装命令，在目标 Linux 服务器的 root 终端执行；缺少 curl 时展开兼容指令。</li><li>未安装或离线时可查看安装指令；在线节点的卸载窗口也可切换“重新安装”。关闭后可随时重新打开。</li><li>卸载默认保留配置与证书，重新安装继承原身份。需要撤销权限时，再在面板删除节点；删除前处理关联隧道。节点自动更新策略在系统设置中维护。</li></ol><button class="button secondary" data-view="nodes">前往节点管理 ${icon('arrow')}</button></section></div>`;
}
document.addEventListener('change',event=>{if(event.target.id==='guide-tunnel'){guideTunnelId=event.target.value;guideBindingId='';guideRouteId='';guideTargetURL='';render();}if(event.target.id==='guide-route'){guideRouteId=event.target.value;guideTargetURL='';render();}if(event.target.id==='guide-target'){guideTargetURL=event.target.value;render();}if(event.target.id==='guide-binding'){guideBindingId=event.target.value;render();}});
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
