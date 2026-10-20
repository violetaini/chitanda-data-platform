'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
(async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ct-node-cards-')),password='Node-Cards-Fixture-2026!',base='http://127.0.0.1:5095';let child,browser,mode='online',count=0,verifiedRoleResponse=false;
 const check=(value,message)=>{assert.ok(value,message);count++;};
 try{
  fs.writeFileSync(path.join(directory,'state.json'),JSON.stringify({version:1,schema:2,events:[],routes:[],relays:[{id:'relay-hk',name:'保留自定义优化机名称',host:'9.9.9.9',port:443,serverName:'control.chitanda.net',token:'a'.repeat(64),psk:'fixture-psk'}],nodes:[{id:'mainland',name:'国内测试机',host:'8.8.8.8',role:'国内接入',token:'b'.repeat(64)},{id:'international',name:'国际测试机',host:'1.1.1.1',role:'国际接入',token:'c'.repeat(64)}],origins:[{id:'custom-business-origin',name:'国际源站',role:'国际源站',host:'8.8.4.4',endpoint:'relay-hk'}]}));
  child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:'ignore',env:{...process.env,CT_PORT:'5095',CT_DATA:directory,CT_USERNAME:'node-cards-admin',CT_PASSWORD_HASH:await createAdminPasswordHash(password),CT_INSECURE:'1',CT_OPENSSL:process.env.CT_OPENSSL||(process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl')}});
  for(let i=0;i<80;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  const {chromium}=require('playwright');browser=await chromium.launch({headless:true});const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/tunnel/api/state',async route=>{
   const response=await route.fetch(),state=await response.json();state.version=15;
   if(!verifiedRoleResponse){verifiedRoleResponse=true;check(state.nodes.find(n=>n.id==='mainland').role==='国内隧道'&&state.nodes.find(n=>n.id==='international').role==='国际隧道入口','legacy stored roles normalize without changing identities');check(JSON.stringify(state.relays[0].entryRoles)===JSON.stringify(['国际隧道入口']),'relay entrance duty derives from configured origin endpoint');}
   const relay={...state.relays[0],online:true,memory:13*1024*1024,uptime:67000,revision:15,certExpires:'2027-10-17T12:00:00Z',certNames:['control.chitanda.net','custom.chitanda.net']};
   relay.ingress={domain:'observed-business.example.com',port:443};state.settings.certificates.profiles=[{id:'fixture-root',rootDomain:'example.com',validity:'valid',distribution:[]}];state.relays=[relay];state.nodes=[{...state.nodes[0],online:mode!=='offline',memory:11*1024*1024,uptime:70000,revision:mode==='pending'?14:15,links:{}}];
   const certificate={fingerprint:'a'.repeat(64),subject:'CN=Observed server',issuer:'CN=Node observed CA',dnsNames:['custom.chitanda.net'],notBefore:'2026-01-01T00:00:00Z',notAfter:'2027-10-17T12:00:00Z'};
   const node=state.nodes[0];node.ingress=mode==='unreported'?null:{domain:'domestic-business.example.com',port:443};const link={relayId:relay.id,transport:'h2',serverName:'custom.chitanda.net',connected:true};node.links[`${relay.id}|h2|custom.chitanda.net`]=link;
   state.routes=[{id:'fixture-forward',source:node.id,target:relay.id,relayId:relay.id,serverName:'custom.chitanda.net',transport:'h2',enabled:mode!=='unassigned',sourceOnline:true,targetOnline:true,relayOnline:true}];
   const observedAt=new Date().toISOString();relay.tls={schema:1,collectedAt:observedAt,entries:[{side:'server',usage:'channel',relayId:relay.id,active:true,minimumVersion:'TLS 1.3',certificate}]};
   node.tls={schema:1,collectedAt:observedAt,entries:[{side:'client',usage:'channel',relayId:relay.id,transport:'h2',serverName:'custom.chitanda.net',active:true,verified:true,version:'TLS 1.3',alpn:'h2',cipher:'TLS_AES_128_GCM_SHA256',observedAt,certificate}]};
   node.tls.entries.push({side:'server',usage:'https-ingress',active:true,certificate:{...certificate,dnsNames:['domestic-business.example.com']}});if(mode==='unreported')node.tls=null;
   if(mode==='rotated')node.tls.entries[1].certificate={...certificate,fingerprint:'c'.repeat(64),notAfter:'2030-02-03T12:00:00Z'};
   if(mode==='unassigned')node.tls.entries=[];
   if(mode==='multiple'){
    const other={...relay,id:'relay-second',name:'第二优化机',entryRoles:[],serverName:'second.chitanda.net',certNames:['alternate.chitanda.net'],certExpires:'2028-03-01T12:00:00Z'};state.relays.push(other);
    node.links[`${other.id}|h3|alternate.chitanda.net`]={...link,relayId:other.id,transport:'h3',serverName:'alternate.chitanda.net'};
    state.routes.push({...state.routes[0],id:'fixture-second',relayId:other.id,target:other.id,transport:'h3',serverName:'alternate.chitanda.net'});
    other.tls={schema:1,collectedAt:observedAt,entries:[{...relay.tls.entries[0],relayId:other.id,certificate:{...certificate,dnsNames:['alternate.chitanda.net'],notAfter:'2028-03-01T12:00:00Z'}}]};
    node.tls.entries.push({...node.tls.entries[0],relayId:other.id,transport:'h3',serverName:'alternate.chitanda.net',alpn:'h3',certificate:{...certificate,fingerprint:'b'.repeat(64),notAfter:'2028-03-01T12:00:00Z'}});
   }
   await route.fulfill({response,json:state});
  });
  await page.goto(base+'/tunnel/');await page.locator('[name=username]').fill('node-cards-admin');await page.locator('[name=password]').fill(password);await page.locator('.login-submit').click();await page.locator('#shell').waitFor({state:'visible'});await page.locator('nav [data-view=nodes]').click();
  check((await page.locator('#content').innerText()).includes('按实际路径自由组合'),'node page explains the chain');check(await page.locator('[data-node-card=relay-hk] .node-kind').innerText()==='优化机 · 国际隧道入口','combined duties stay on the actual relay card');
  await page.locator('[data-action=new-node]').click();check(JSON.stringify(await page.locator('#node-form [name=purpose] option').allTextContents())===JSON.stringify(['国际隧道入口','优化机','国内隧道']),'one purpose selector has the three agreed terms');check(await page.locator('#node-form [name=region],#node-form [name=kind]').count()===0,'no second node-type or region selector');await page.locator('#node-form [name=purpose]').selectOption('relay');check(await page.locator('#new-relay-fields').isVisible(),'optimizer exposes its listener');await page.locator('#node-form [name=purpose]').selectOption('mainland');check(!(await page.locator('#new-relay-fields').isVisible()),'domestic tunnel hides optimizer settings');await page.locator('#node-dialog').getByRole('button',{name:'关闭',exact:true}).click();
  const agent=page.locator('[data-node-card=mainland]'),relay=page.locator('[data-node-card=relay-hk]');
  await agent.locator('[data-edit-node]').click();check(await page.locator('#node-edit-form [name=certificateRoot] option[value="example.com"]').count()===1,'node management offers matching managed roots');check(await page.locator('#node-edit-form [data-node-certificate-choice]').isVisible(),'certificate assignment is maintained in node management');await page.locator('#node-edit-form [name=certificateRoot]').selectOption('example.com');await page.locator('#node-edit-form').getByRole('button',{name:'取消',exact:true}).click();
  for(const width of [1440,1024,390]){
   await page.setViewportSize({width,height:1050});await page.evaluate(()=>refresh());
   check(await agent.locator('[data-node-field=ingress]').count()===0,'node cards omit tunnel-owned business entries');
   check(await relay.locator('[data-node-field=ingress]').count()===0,'relay cards omit tunnel-owned business entries');
   check(await agent.locator('.node-tls,[data-node-field=sni],[data-node-field=tls]').count()===0,'node cards omit TLS and SNI details');
   check(JSON.stringify(await agent.locator('.node-metrics [data-node-field]').evaluateAll(xs=>xs.map(x=>x.dataset.nodeField)))===JSON.stringify(await relay.locator('.node-metrics [data-node-field]').evaluateAll(xs=>xs.map(x=>x.dataset.nodeField))),'same metrics and ordering');
   check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no horizontal overflow');
   if(width>=1024){const a=await agent.locator('.node-card-footer').boundingBox(),b=await relay.locator('.node-card-footer').boundingBox();check(Math.abs(a.y-b.y)<1,'card actions align');}
   const output=path.resolve('tmp/node-cards-qa');fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,`nodes-${width}.png`),fullPage:true});
  }
  mode='unreported';await page.evaluate(()=>refresh());check(await agent.locator('[data-node-field=ingress]').count()===0,'no node-level entry placeholder');
  mode='multiple';await page.evaluate(()=>refresh());check(await page.locator('[data-node-card]').count()===3,'arbitrary added nodes automatically render');check(await page.locator('[data-node-card=relay-second] .node-kind').innerText()==='优化机','unrelated optimizer does not inherit another origin duty');
  check((await agent.locator('[data-node-field=certificate]').innerText()).includes('有效'),'node card shows brief certificate validity');mode='rotated';await page.evaluate(()=>refresh());check((await agent.locator('[data-node-field=certificate]').innerText()).includes('2030'),'node expiry follows observed rotation');mode='offline';await page.evaluate(()=>refresh());check((await agent.locator('[data-node-field=certificate]').innerText()).includes('离线'),'offline certificate status is explicit');await page.locator('nav [data-view=settings]').click();check(await page.locator('.certificate-observations').count()===0,'per-node observations are removed from settings');
  check(errors.length===0,'browser errors: '+errors.join(';'));console.log(`PASS ${count} node-card checks: concise cards, tunnel-owned HTTPS entries, brief observed certificate status and multiple nodes.`);
 }finally{if(browser)await browser.close();if(child)await new Promise(resolve=>{child.once('exit',resolve);child.kill();});fs.rmSync(directory,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
