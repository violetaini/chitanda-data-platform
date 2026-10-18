'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
(async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ct-node-cards-')),password='Node-Cards-Fixture-2026!',base='http://127.0.0.1:5095';let child,browser,mode='online',count=0;
 const check=(value,message)=>{assert.ok(value,message);count++;};
 try{
  child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:'ignore',env:{...process.env,CT_PORT:'5095',CT_DATA:directory,CT_USERNAME:'node-cards-admin',CT_PASSWORD_HASH:await createAdminPasswordHash(password),CT_INSECURE:'1',CT_OPENSSL:process.env.CT_OPENSSL||(process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl')}});
  for(let i=0;i<80;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  const {chromium}=require('playwright');browser=await chromium.launch({headless:true});const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/tunnel/api/state',async route=>{
   const response=await route.fetch(),state=await response.json();state.version=15;
   const relay={...state.relays[0],online:true,memory:13*1024*1024,uptime:67000,revision:15,certExpires:'2027-10-17T12:00:00Z',certNames:['control.chitanda.net','custom.chitanda.net']};
   state.relays=[relay];state.nodes=[{...state.nodes[0],online:mode!=='offline',memory:11*1024*1024,uptime:70000,revision:mode==='pending'?14:15,links:{}}];
   const certificate={fingerprint:'a'.repeat(64),subject:'CN=Observed server',issuer:'CN=Node observed CA',dnsNames:['custom.chitanda.net'],notBefore:'2026-01-01T00:00:00Z',notAfter:'2027-10-17T12:00:00Z'};
   const node=state.nodes[0],link={relayId:relay.id,transport:'h2',serverName:'custom.chitanda.net',connected:true};node.links[`${relay.id}|h2|custom.chitanda.net`]=link;
   state.routes=[{id:'fixture-forward',source:node.id,target:relay.id,relayId:relay.id,serverName:'custom.chitanda.net',transport:'h2',enabled:mode!=='unassigned',sourceOnline:true,targetOnline:true,relayOnline:true}];
   const observedAt=new Date().toISOString();relay.tls={schema:1,collectedAt:observedAt,entries:[{side:'server',usage:'channel',relayId:relay.id,active:true,minimumVersion:'TLS 1.3',certificate}]};
   node.tls={schema:1,collectedAt:observedAt,entries:[{side:'client',usage:'channel',relayId:relay.id,transport:'h2',serverName:'custom.chitanda.net',active:true,verified:true,version:'TLS 1.3',alpn:'h2',cipher:'TLS_AES_128_GCM_SHA256',observedAt,certificate}]};
   if(mode==='unreported')node.tls=null;
   if(mode==='rotated')node.tls.entries[0].certificate={...certificate,fingerprint:'c'.repeat(64),notAfter:'2030-02-03T12:00:00Z'};
   if(mode==='unassigned')node.tls.entries=[];
   if(mode==='multiple'){
    const other={...relay,id:'relay-second',name:'第二优化节点',serverName:'second.chitanda.net',certNames:['alternate.chitanda.net'],certExpires:'2028-03-01T12:00:00Z'};state.relays.push(other);
    node.links[`${other.id}|h3|alternate.chitanda.net`]={...link,relayId:other.id,transport:'h3',serverName:'alternate.chitanda.net'};
    state.routes.push({...state.routes[0],id:'fixture-second',relayId:other.id,target:other.id,transport:'h3',serverName:'alternate.chitanda.net'});
    other.tls={schema:1,collectedAt:observedAt,entries:[{...relay.tls.entries[0],relayId:other.id,certificate:{...certificate,dnsNames:['alternate.chitanda.net'],notAfter:'2028-03-01T12:00:00Z'}}]};
    node.tls.entries.push({...node.tls.entries[0],relayId:other.id,transport:'h3',serverName:'alternate.chitanda.net',alpn:'h3',certificate:{...certificate,fingerprint:'b'.repeat(64),notAfter:'2028-03-01T12:00:00Z'}});
   }
   await route.fulfill({response,json:state});
  });
  await page.goto(base+'/tunnel/');await page.locator('[name=username]').fill('node-cards-admin');await page.locator('[name=password]').fill(password);await page.locator('.login-submit').click();await page.locator('#shell').waitFor({state:'visible'});await page.locator('nav [data-view=nodes]').click();
  const agent=page.locator('[data-node-card=mainland]'),relay=page.locator('[data-node-card=relay-hk]');
  for(const width of [1440,1024,390]){
   await page.setViewportSize({width,height:1050});await page.evaluate(()=>refresh());
   check(await agent.locator('[data-node-field=sni]').innerText().then(s=>s.includes('custom.chitanda.net')),'agent shows the route SNI, not relay default');
   check((await agent.locator('[data-node-field=tls]').innerText()).includes('最近握手验证通过'),'current online link verified');
   check((await agent.locator('[data-node-field=certificate]').innerText()).includes('2027/10/17'),'agent shows peer certificate expiry');
   check((await agent.innerText()).includes('对端证书')&&(await relay.innerText()).includes('本节点证书到期'),'certificate ownership is explicit');
   check(JSON.stringify(await agent.locator('.node-metrics [data-node-field]').evaluateAll(xs=>xs.map(x=>x.dataset.nodeField)))===JSON.stringify(await relay.locator('.node-metrics [data-node-field]').evaluateAll(xs=>xs.map(x=>x.dataset.nodeField))),'same metrics and ordering');
   check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no horizontal overflow');
   if(width>=1024){const a=await agent.locator('.node-card-footer').boundingBox(),b=await relay.locator('.node-card-footer').boundingBox();check(Math.abs(a.y-b.y)<1,'card actions align');}
   const output=path.resolve('tmp/node-cards-qa');fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,`nodes-${width}.png`),fullPage:true});
  }
  mode='offline';await page.evaluate(()=>refresh());check((await agent.locator('[data-node-field=tls]').innerText()).includes('节点离线 · 保留上次采样'),'offline cached links are not reported verified');
  mode='pending';await page.evaluate(()=>refresh());check((await agent.locator('[data-node-field=tls]').innerText()).includes('配置同步中 · 采样待更新'),'stale revision is not reported verified');
  mode='unreported';await page.evaluate(()=>refresh());check((await agent.innerText()).includes('待节点上报'),'old node shows no fabricated TLS metadata');check(await agent.locator('[data-node-field=certificate]').count()===0,'no certificate expiry is inferred from relay configuration');
  mode='unassigned';await page.evaluate(()=>refresh());check((await agent.innerText()).includes('待节点上报'),'empty observations stay unreported');
  mode='rotated';await page.evaluate(()=>refresh());check((await agent.locator('[data-node-field=certificate]').innerText()).includes('2030/2/3'),'renewed peer observation updates without changing UI or controller relay metadata');
  mode='multiple';await page.evaluate(()=>refresh());check(await agent.locator('[data-node-field=sni] .node-tls-entry').count()===2,'multiple observed peers shown');check((await agent.innerText()).includes('alternate.chitanda.net')&&(await agent.innerText()).includes('2028/3/1'),'each observed peer retains its own SNI and expiry');check(await agent.locator('[data-node-field=tls]').filter({hasText:'最近握手验证通过'}).count()===2,'each active observed handshake is shown');
  check(errors.length===0,'browser errors: '+errors.join(';'));console.log(`PASS ${count} node-card checks: shared rows, TLS ownership, route SNI, certificate expiry, offline/pending states and multiple peers.`);
 }finally{if(browser)await browser.close();if(child)await new Promise(resolve=>{child.once('exit',resolve);child.kill();});fs.rmSync(directory,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
