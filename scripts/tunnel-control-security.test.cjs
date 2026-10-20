'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const createDefense=require('../deploy/tunnel-control/login-defense.cjs'),graphs=require('../deploy/tunnel-control/public/graph-model.js');
test('login protection survives restarts, counts concurrent attempts and escalates locks',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-defense-'));let now=1800000000000;
 try{let defense=createDefense(dir,{now:()=>now});const ticket=defense.begin('123.119.187.76');assert.throws(()=>defense.begin('123.119.187.76'),e=>e.status===429);defense.failure(ticket);defense.finish(ticket);
 for(let i=2;i<=5;i++){const t=defense.begin('123.119.187.76');defense.failure(t);defense.finish(t);if(i<5){assert.throws(()=>defense.begin('123.119.187.76'),e=>e.status===429);now+=2**(i-1)*1000+1;}}
 defense=createDefense(dir,{now:()=>now});assert.throws(()=>defense.begin('123.119.187.76'),e=>e.retryAfter===900);now+=900001;
 for(let i=1;i<=5;i++){const t=defense.begin('123.119.187.76');defense.failure(t);defense.finish(t);if(i>=2&&i<5)now+=2**(i-1)*1000+1;}
 assert.throws(()=>defense.begin('123.119.187.76'),e=>e.retryAfter===1800);
 assert.ok(!fs.readFileSync(path.join(dir,'login-defense.json'),'utf8').includes('password'));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('aggregate protection covers alternate usernames and allowed source addresses',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-defense-'));let now=1800000000000;
 try{const defense=createDefense(dir,{now:()=>now});for(let i=0;i<10;i++){const ip=['123.119.187.76','127.0.0.1','::1'][i%3],t=defense.begin(ip);defense.failure(t);defense.finish(t);if(i<9)now+=31000;}assert.throws(()=>defense.begin('new-source'),e=>e.retryAfter===900);const account=defense.begin('new-source','account');defense.success(account);defense.finish(account);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('topology is generated from arbitrary node identities, includes unassigned nodes and avoids overlap',()=>{
 const nodes=Array.from({length:64},(_,i)=>({id:'custom-'+i,name:'节点 '+i,kind:i%4?'agent':'relay'})),edges=nodes.slice(1).flatMap((n,i)=>[{source:nodes[i].id,target:n.id,routeId:'route-'+i,enabled:true,ready:true,transport:'h2'},{source:n.id,target:nodes[i].id,routeId:'reverse-'+i,enabled:true,ready:true,transport:'h3'}]);
 const graph=graphs.aggregateGraph({nodes:[...nodes,{id:'unassigned'}],edges}),layout=graphs.layoutGraph(graph);assert.equal(layout.nodes.length,65);assert.equal(graph.edges.length,63);assert.equal(new Set(layout.nodes.map(n=>n.id)).size,65);assert.ok(graph.edges.every(e=>e.directions.length===2));
 for(let i=0;i<layout.nodes.length;i++)for(let j=i+1;j<layout.nodes.length;j++){const a=layout.nodes[i],b=layout.nodes[j];assert.ok(Math.abs(a.x-b.x)>=159.9||Math.abs(a.y-b.y)>=71.9,'node collision');}
 assert.equal(graphs.aggregateGraph({nodes:[],edges:[]}).nodes.length,0);
 const renamed=graphs.aggregateGraph({nodes:[{id:'new-id',name:'Renamed'}],edges:[{source:'removed',target:'new-id'}]});assert.equal(renamed.edges.length,0);
});
test('origin topology separates arbitrary business hosts from multiple tunnel endpoints',()=>{
 const nodes=[{id:'control',kind:'control'},...Array.from({length:4},(_,i)=>({id:'endpoint-'+i,kind:i<2?'agent':'relay'})),...Array.from({length:8},(_,i)=>({id:'business-'+i,kind:'origin',endpoint:'endpoint-'+i%4}))];
 const edges=nodes.filter(n=>n.kind==='origin').map(n=>({source:n.id,target:n.endpoint,kind:'https',enabled:true}));
 const layout=graphs.layoutGraph(graphs.aggregateGraph({nodes,edges}));assert.equal(layout.nodes.length,13);assert.equal(layout.edges.length,8);
 for(const n of layout.nodes){assert.ok(n.x-n.width/2>=0&&n.x+n.width/2<=layout.width);assert.ok(n.y-n.height/2>=0&&n.y+n.height/2<=layout.height);}
 for(let i=0;i<layout.nodes.length;i++)for(let j=i+1;j<layout.nodes.length;j++){const a=layout.nodes[i],b=layout.nodes[j];assert.ok(Math.abs(a.x-b.x)>=(a.width+b.width)/2||Math.abs(a.y-b.y)>=(a.height+b.height)/2,'node collision');}
});
test('chart uses actual time and counter deltas, preserves zero and gaps, detects process restart',()=>{
 const now=1800000000000,points=[{at:now-90000,rx:0,tx:0,uptime:10},{at:now-75000,rx:1500,tx:0,uptime:25},{at:now-60000,rx:1500,tx:1500,uptime:40},{at:now-10000,rx:1700,tx:1700,uptime:90},{at:now,rx:0,tx:0,uptime:1}],model=graphs.chartModel(points,{now});
 assert.equal(model.points[0].rx,100);assert.equal(model.points[0].tx,0);assert.equal(model.points[1].rx,0);assert.equal(model.points[1].tx,100);assert.equal(model.points[2].rx,null);assert.equal(model.points[3].rx,null);assert.equal(model.stale,true);assert.ok(model.top>=100);assert.equal(graphs.chartModel([],{now}).points.length,0);
 const fresh=graphs.chartModel(points.slice(0,3),{now:now-60000});assert.equal(fresh.stale,false);assert.equal(fresh.latest.rx,0);assert.equal(graphs.chartModel([{at:now-1000,rx:1,tx:1}],{now}).points.length,0);
 assert.match(graphs.smoothPath([{x:0,y:0},{x:15,y:1},{x:30,y:0}]),/C/);
});
test('management privileges, session source binding, CSRF, origin and scoped node credentials',async()=>{
 const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-boundary-')),password='Boundary-2026!',base='http://127.0.0.1:5097';
 const child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:'ignore',env:{...process.env,CT_PORT:'5097',CT_DATA:dir,CT_USERNAME:'boundary-admin',CT_PASSWORD_HASH:await createAdminPasswordHash(password),CT_INSECURE:'1',CT_OPENSSL:process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl'}});
 try{for(let i=0;i<80;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const request=(endpoint,method='GET',headers={},value)=>fetch(base+endpoint,{method,headers,...(value===undefined?{}:{body:JSON.stringify(value)})});
 for(const endpoint of ['/tunnel/api/state','/tunnel/api/enrollment','/tunnel/api/security','/tunnel/api/profile','/tunnel/api/account','/tunnel/api/settings','/tunnel/api/ports/available?nodeId=mainland'])assert.equal((await request(endpoint)).status,401);
 const login=await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},{username:'boundary-admin',password});assert.equal(login.status,200);const cookie=login.headers.get('set-cookie'),value=await login.json(),headers={Cookie:cookie.split(';')[0],'X-CSRF-Token':value.csrf,'Content-Type':'application/json'};
 assert.equal((await request('/tunnel/api/domains/0000000000000000','PATCH',{'Content-Type':'application/json'},{ttl:1})).status,401);
 assert.equal((await request('/tunnel/api/domains/0000000000000000','PATCH',{Cookie:headers.Cookie,'Content-Type':'application/json'},{ttl:1})).status,403);
 assert.equal((await request('/tunnel/api/domains/0000000000000000','PATCH',{...headers,Origin:'https://untrusted.example'},{ttl:1})).status,403);
 assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Strict/);
 assert.equal((await request('/tunnel/api/state','GET',{...headers,'X-Real-IP':'123.119.187.76'})).status,401);
 assert.equal((await request('/tunnel/api/nodes','POST',{Cookie:headers.Cookie,'Content-Type':'application/json'},{name:'bad'})).status,403);
 assert.equal((await request('/tunnel/api/nodes','POST',{...headers,Origin:'https://untrusted.example'},{name:'bad'})).status,403);
 assert.equal((await request('/tunnel/api/login','POST',{'Content-Type':'application/json','Sec-Fetch-Site':'cross-site'},{username:'boundary-admin',password})).status,403);
 assert.equal((await request('/tunnel/api/login','POST',{},{})).status,415);
 for(const endpoint of ['/tunnel/','/tunnel/graph-model.js','/tunnel/dashboard.js','/tunnel/security.js','/tunnel/api/security'])assert.equal((await request(endpoint,'GET',{'X-Real-IP':'8.8.8.8','X-Forwarded-For':'123.119.187.76'})).status,403);
 const beforeSettings=(await(await request('/tunnel/api/state','GET',headers)).json()).version;
 assert.equal((await request('/tunnel/api/settings','PATCH',{Cookie:headers.Cookie,'Content-Type':'application/json'},{routeChecks:{enabled:false}})).status,403);
 assert.equal((await request('/tunnel/api/settings','PATCH',{...headers,Origin:'https://untrusted.example'},{routeChecks:{enabled:false}})).status,403);
 assert.equal((await request('/tunnel/api/settings','GET',{...headers,'X-Real-IP':'8.8.8.8'})).status,403);
 assert.equal((await request('/tunnel/api/settings','PATCH',headers,{allowedIPs:['0.0.0.0']})).status,400);
 assert.equal((await request('/tunnel/api/settings','PATCH',headers,{routeChecks:{intervalSeconds:3600}})).status,400);
 assert.equal((await request('/tunnel/api/settings','PATCH',headers,{routeChecks:{enabled:false}})).status,200);
 assert.equal((await(await request('/tunnel/api/settings','GET',headers)).json()).routeChecks.enabled,false);
 assert.equal((await(await request('/tunnel/api/state','GET',headers)).json()).version,beforeSettings);
 await request('/tunnel/api/routes','POST',headers,{name:'Scope test',source:'mainland',target:'international',listenPort:15081,targetPort:5081});
 const telemetryCertificate={fingerprint:'a'.repeat(64),subject:'CN=Observed',issuer:'CN=CA',dnsNames:['control.chitanda.net'],notBefore:'2026-01-01T00:00:00Z',notAfter:'2027-12-31T00:00:00Z',keyPEM:'PRIVATE-CERTIFICATE-MUST-NOT-PASS'};
 const newNode=await(await request('/tunnel/api/nodes','POST',headers,{name:'Unassigned'})).json();
 const enroll=async id=>(await(await request('/tunnel/api/enrollment','POST',headers,{id})).json());
 const mainland=await enroll('mainland'),international=await enroll('international'),relay=await enroll('relay-hk');
 const sync=async enrollment=>(await request('/transit-node/sync','POST',{'X-Node-ID':enrollment.id,Authorization:'Bearer '+enrollment.token,'Content-Type':'application/json'},{}));
 const observation={side:'client',usage:'channel',relayId:'relay-hk',transport:'h2',serverName:'control.chitanda.net',active:true,verified:true,version:'TLS 1.3',alpn:'h2',observedAt:new Date().toISOString(),certificate:telemetryCertificate,token:'OBSERVATION-SECRET-MUST-NOT-PASS'};
 await request('/transit-node/sync','POST',{'X-Node-ID':mainland.id,Authorization:'Bearer '+mainland.token,'Content-Type':'application/json'},{revision:2,tls:{schema:1,collectedAt:new Date().toISOString(),entries:[observation,{...observation,relayId:'unrelated-optimizer'},{...observation,side:'server'}]}});
 const sampled=await(await request('/tunnel/api/state','GET',headers)).json(),reported=sampled.nodes.find(n=>n.id===mainland.id).tls;
 assert.equal(reported.entries.length,1);assert.equal(reported.entries[0].certificate.notAfter,'2027-12-31T00:00:00.000Z');assert.equal(reported.entries[0].serverName,'control.chitanda.net');assert.ok(!JSON.stringify(reported).includes('MUST-NOT-PASS'));assert.ok(sampled.relays.find(n=>n.id==='relay-hk').tls==null);
 const relayConfig=await(await sync(relay)).json(),agentConfig=await(await sync(mainland)).json();assert.equal(relayConfig.nodes.length,2);assert.ok(!relayConfig.nodes.some(n=>n.id===newNode.node.id));
 assert.ok(relayConfig.nodes.every(n=>n.token!==mainland.token&&n.token!==international.token));const scoped=agentConfig.relays[0].brokerToken;assert.equal(scoped,relayConfig.nodes.find(n=>n.id==='mainland').token);
 assert.equal((await request('/transit-node/sync','POST',{'X-Node-ID':'mainland',Authorization:'Bearer '+scoped,'Content-Type':'application/json'},{})).status,401);
 const relay2=await(await request('/tunnel/api/nodes','POST',headers,{kind:'relay',name:'Independent optimizer'})).json();await request('/tunnel/api/routes','POST',headers,{name:'Second scope',source:'mainland',target:'international',relayId:relay2.node.id,listenPort:15082,targetPort:5081});const secondIdentity=await enroll(relay2.node.id);await request('/transit-node/sync','POST',{'X-Node-ID':secondIdentity.id,Authorization:'Bearer '+secondIdentity.token,'Content-Type':'application/json','X-Real-IP':'198.51.100.8'},{});const twoScopes=await(await sync(mainland)).json();assert.equal(twoScopes.relays.length,2);assert.notEqual(twoScopes.relays[0].brokerToken,twoScopes.relays[1].brokerToken);
 assert.equal((await request('/tunnel/api/state','GET',{Authorization:'Bearer '+mainland.token})).status,401);
 assert.ok(!JSON.stringify(agentConfig).includes('keyPEM')&&!JSON.stringify(agentConfig).includes(international.token));
 const state=await(await request('/tunnel/api/state','GET',headers)).json();assert.ok(state.topology.nodes.some(n=>n.id===newNode.node.id));assert.equal(new Set(state.topology.nodes.map(n=>n.id)).size,state.topology.nodes.length);assert.ok(!JSON.stringify(state).includes(scoped));
 const localEndpoint=await request('/tunnel/api/routes','POST',headers,{name:'Relay endpoint',source:'mainland',target:'relay-hk',relayId:'relay-hk',listenPort:15084,targetPort:16082});assert.equal(localEndpoint.status,201);
 const relaySource=await request('/tunnel/api/routes','POST',headers,{name:'Relay source',source:'relay-hk',target:'mainland',relayId:'relay-hk',listenPort:15084,targetPort:16082});assert.equal(relaySource.status,201);
 const nativeConfig=await(await sync(relay)).json();const selfIdentity=nativeConfig.nodes.find(n=>n.id==='relay-hk');assert.ok(selfIdentity&&selfIdentity.token!==relay.token);
 const nodeConfig=await(await sync(mainland)).json();assert.ok(!JSON.stringify(nodeConfig).includes(selfIdentity.token));
 assert.equal((await request('/tunnel/api/routes','POST',headers,{name:'Wrong relay endpoint',source:'mainland',target:'relay-hk',relayId:relay2.node.id,listenPort:15085,targetPort:16082})).status,400);
 assert.equal((await request('/tunnel/api/routes','POST',headers,{name:'Forbidden local management',source:'mainland',target:'relay-hk',relayId:'relay-hk',listenPort:15085,targetPort:5092})).status,400);
 const live=await(await request('/tunnel/api/state','GET',headers)).json(),testRoute=live.routes.find(r=>r.name==='Scope test');
 const probePath='routes/'+testRoute.id+'/test';
 assert.equal((await request('/tunnel/api/'+probePath,'POST',{'Content-Type':'application/json'},{})).status,401);
 assert.equal((await request('/tunnel/api/'+probePath,'POST',{Cookie:headers.Cookie,'Content-Type':'application/json'},{})).status,403);
 assert.equal((await request('/tunnel/api/'+probePath,'POST',headers,{host:'unrelated.example',port:22})).status,400);
 for(const identity of [mainland,international,relay])await request('/transit-node/sync','POST',{'X-Node-ID':identity.id,Authorization:'Bearer '+identity.token,'Content-Type':'application/json'},{revision:live.version,capabilities:{routeProbe:1}});
 const queued=await request('/tunnel/api/'+probePath,'POST',headers,{});assert.equal(queued.status,202);const task=(await queued.json()).test;
 assert.equal((await request('/tunnel/api/'+probePath,'POST',headers,{})).status,409);
 const targetJobs=await(await request('/transit-node/sync','POST',{'X-Node-ID':international.id,Authorization:'Bearer '+international.token,'Content-Type':'application/json'},{revision:live.version,capabilities:{routeProbe:1}})).json();assert.equal(targetJobs.checks.length,0);
 const sourceJobs=await(await request('/transit-node/sync','POST',{'X-Node-ID':mainland.id,Authorization:'Bearer '+mainland.token,'Content-Type':'application/json'},{revision:live.version,capabilities:{routeProbe:1}})).json();assert.equal(sourceJobs.checks[0].id,task.id);
 const checkResult={id:task.id,routeId:testRoute.id,revision:live.version,status:'complete',attempts:3,samples:[2,4,6]};
 await request('/transit-node/sync','POST',{'X-Node-ID':international.id,Authorization:'Bearer '+international.token,'Content-Type':'application/json'},{revision:live.version,routeChecks:[checkResult]});
 assert.equal((await(await request('/tunnel/api/state','GET',headers)).json()).routes.find(r=>r.id===testRoute.id).test.status,'running');
 await request('/transit-node/sync','POST',{'X-Node-ID':mainland.id,Authorization:'Bearer '+mainland.token,'Content-Type':'application/json'},{revision:live.version,routeChecks:[checkResult]});
 const completed=(await(await request('/tunnel/api/state','GET',headers)).json()).routes.find(r=>r.id===testRoute.id).test;assert.equal(completed.status,'success');assert.equal(completed.latency.average,4);
 const privateState=JSON.parse(fs.readFileSync(path.join(dir,'state.json'),'utf8')),pair=privateState.relays[0];
 const certPayload={purpose:'channel',mode:'custom',certPEM:pair.certPEM,keyPEM:pair.keyPEM};
 assert.equal((await request('/tunnel/api/certificates','PUT',{Cookie:headers.Cookie,'Content-Type':'application/json'},certPayload)).status,403);
 assert.equal((await request('/tunnel/api/certificates','PUT',headers,{...certPayload,keyPEM:'bad'})).status,400);
 assert.equal((await request('/tunnel/api/certificates','PUT',headers,certPayload)).status,200);
 const publicSettings=JSON.stringify(await(await request('/tunnel/api/settings','GET',headers)).json());assert.ok(!publicSettings.includes('PRIVATE KEY')&&!publicSettings.includes('certPEM')&&!publicSettings.includes('keyPEM'));
 const incompatible=await request('/tunnel/api/routes','POST',headers,{name:'Uncovered SNI',source:'mainland',target:'international',relayId:'relay-hk',listenPort:15301,targetPort:5081,serverName:'not-in-cert.example'});assert.equal(incompatible.status,400);
 const streamRoute=await request('/tunnel/api/routes','POST',headers,{name:'Native Stream',source:'mainland',target:'international',relayId:'relay-hk',listenPort:15301,targetPort:5081,transport:'stream',serverName:'ignored.invalid'});assert.equal(streamRoute.status,201);assert.equal((await streamRoute.json()).route.serverName,'');
 await request('/transit-node/sync','POST',{'X-Node-ID':mainland.id,Authorization:'Bearer '+mainland.token,'Content-Type':'application/json'},{ingress:{domain:'control.chitanda.net',port:443}});
 const httpsPayload={...certPayload,purpose:'https',nodeIds:['mainland']};assert.equal((await request('/tunnel/api/certificates','PUT',headers,httpsPayload)).status,200);
 assert.ok((await(await sync(mainland)).json()).httpsCertificate.keyPEM.includes('PRIVATE KEY'));assert.equal((await(await sync(international)).json()).httpsCertificate,null);assert.equal((await(await sync(relay)).json()).httpsCertificate,null);
 assert.equal((await request('/tunnel/api/certificates','PUT',headers,{purpose:'https',mode:'auto'})).status,200);assert.equal((await(await sync(mainland)).json()).httpsCertificate,null);
 assert.equal((await request('/tunnel/api/certificates','PUT',headers,{purpose:'channel',mode:'auto'})).status,200);
 const security=await(await request('/tunnel/api/security','GET',headers)).json();assert.equal(security.policy.failureLimit,5);assert.ok(security.events.every(e=>!('password' in e)&&!('username' in e)));
 for(const [purpose,role,kind] of [['international','国际隧道入口','agent'],['relay','优化机','relay'],['mainland','国内隧道','agent']]){const response=await request('/tunnel/api/nodes','POST',headers,{name:'Purpose '+purpose,purpose});assert.equal(response.status,201);const {node}=await response.json();assert.equal(node.role,role);assert.equal(node.kind,kind);assert.equal((await enroll(node.id)).role,kind);assert.equal((await request('/tunnel/api/nodes/'+node.id,'DELETE',headers,{})).status,200);}
 assert.equal((await request('/tunnel/api/nodes','POST',headers,{name:'Invalid purpose',purpose:'unknown'})).status,400);
 const chainInput={name:'Chained pair',mode:'bidirectional',source:'mainland',target:'international',relayIds:['relay-hk',relay2.node.id],listenPort:15660,targetPort:16660,reverseListenPort:15661,reverseTargetPort:16661,transport:'h2',serverName:'control.chitanda.net'};
 const createdChain=await request('/tunnel/api/tunnels','POST',headers,chainInput);assert.equal(createdChain.status,201);const chainTunnel=(await createdChain.json()).tunnel;
 const httpURL='/tunnel/api/tunnels/'+chainTunnel.id+'/http';assert.equal((await request(httpURL,'PUT',{'Content-Type':'application/json'},{enabled:false,directions:[]})).status,401);assert.equal((await request(httpURL,'PUT',{Cookie:headers.Cookie,'Content-Type':'application/json'},{enabled:false,directions:[]})).status,403);assert.equal((await request(httpURL,'PUT',{...headers,Origin:'https://untrusted.example'},{enabled:false,directions:[]})).status,403);assert.equal((await request(httpURL,'PUT',headers,{enabled:false,directions:[]})).status,200);
 const tokenURL='/tunnel/api/tunnels/'+chainTunnel.id+'/token';assert.equal((await request(tokenURL,'POST',{'Content-Type':'application/json'},{})).status,401);assert.equal((await request(tokenURL,'POST',{Cookie:headers.Cookie,'Content-Type':'application/json'},{})).status,403);const tokenResponse=await request(tokenURL,'POST',headers,{});assert.equal(tokenResponse.status,200);const tunnelToken=(await tokenResponse.json()).token;assert.match(tunnelToken,/^[a-f0-9]{64}$/);assert.equal((await request(tokenURL,'GET',headers)).status,404);assert.equal((await request(tokenURL,'POST',{...headers,Origin:'https://untrusted.example'},{})).status,403);assert.equal((await request('/tunnel/api/tunnels/missing/token','POST',headers,{})).status,404);assert.ok(!JSON.stringify(await(await request('/tunnel/api/state','GET',headers)).json()).includes(tunnelToken),'state must not return tunnel secrets');assert.ok(!JSON.stringify(chainTunnel).includes(tunnelToken),'CRUD response must not return tunnel secrets');
 assert.equal((await request(tokenURL+'/reset','POST',{Cookie:headers.Cookie,'Content-Type':'application/json'},{})).status,403);assert.equal((await request(tokenURL+'/reset','POST',headers,{})).status,200);const resetToken=(await(await request(tokenURL,'POST',headers,{})).json()).token;assert.notEqual(resetToken,tunnelToken);assert.ok(!JSON.stringify(await(await request('/tunnel/api/state','GET',headers)).json()).includes(resetToken));
 const chainState=await(await request('/tunnel/api/state','GET',headers)).json(),chainRoutes=chainTunnel.routeIds.map(id=>chainState.routes.find(r=>r.id===id));assert.deepEqual(chainRoutes.map(r=>r.relayIds),[['relay-hk',relay2.node.id],[relay2.node.id,'relay-hk']]);
 assert.ok(!(await(await sync(relay)).json()).routes.some(r=>r.id===chainRoutes[0].id),'legacy peers cannot receive a partial interpretation of a chained route');
 for(const identity of [mainland,international,relay,await enroll(relay2.node.id)])await request('/transit-node/sync','POST',{'X-Node-ID':identity.id,Authorization:'Bearer '+identity.token,'Content-Type':'application/json'},{revision:chainState.version,capabilities:{routeProbe:1,relayChain:1}});
 const chainSourceConfig=await(await sync(mainland)).json(),chainTargetConfig=await(await sync(international)).json(),hopOne=await(await sync(relay)).json(),hopTwo=await(await sync(await enroll(relay2.node.id))).json();
 assert.ok(hopOne.routes.some(r=>r.id===chainRoutes[0].id)&&hopTwo.routes.some(r=>r.id===chainRoutes[0].id));assert.ok(hopTwo.nodes.some(n=>n.id==='relay-hk'));assert.ok(hopOne.relays.some(n=>n.id===relay2.node.id));
 const scopedNext=hopOne.relays.find(n=>n.id===relay2.node.id).brokerToken;assert.ok(!JSON.stringify(chainSourceConfig).includes(scopedNext)&&!JSON.stringify(chainTargetConfig).includes(scopedNext));assert.ok(!JSON.stringify(hopOne).includes('ca.key'));
 assert.equal(chainState.topology.edges.filter(e=>e.routeId===chainRoutes[0].id).length,3);
 for(const relayIds of [['relay-hk','relay-hk'],['missing'],Array(9).fill('relay-hk')])assert.equal((await request('/tunnel/api/tunnels','POST',headers,{...chainInput,relayIds,listenPort:15662})).status,400);
 const beforeDirect=await(await request('/tunnel/api/state','GET',headers)).json();
 const directResponse=await request('/tunnel/api/tunnels','POST',headers,{name:'Only two endpoints',mode:'bidirectional',source:'mainland',target:'international',relayIds:[],listenPort:15700,targetPort:16700,reverseListenPort:15701,reverseTargetPort:16701,serverName:'control.chitanda.net'});assert.equal(directResponse.status,201);const directTunnel=(await directResponse.json()).tunnel;
 const directState=await(await request('/tunnel/api/state','GET',headers)).json(),directRoutes=directTunnel.routeIds.map(id=>directState.routes.find(r=>r.id===id));assert.ok(directRoutes.every(r=>r.direct&&r.relayId==='international'));assert.ok(directRoutes.every(r=>require('../deploy/tunnel-control/route-path.cjs').path(r).length===2));
 assert.ok(!(await(await sync(mainland)).json()).routes.some(r=>directTunnel.routeIds.includes(r.id)),'direct path withheld from old endpoints');
 for(const identity of [mainland,international])await request('/transit-node/sync','POST',{'X-Node-ID':identity.id,Authorization:'Bearer '+identity.token,'Content-Type':'application/json'},{revision:directState.version,capabilities:{routeProbe:1,relayChain:1,directEndpoint:1}});
 const directSource=await(await sync(mainland)).json(),directTarget=await(await sync(international)).json(),unrelated=await(await sync(relay)).json();assert.ok(directSource.routes.some(r=>directTunnel.routeIds.includes(r.id)));assert.equal(directTarget.role,'agent');assert.equal(directTarget.selfRelay.id,'international');assert.equal(directTarget.selfRelay.port,18443);assert.ok(directTarget.selfRelay.certPEM.includes('CERTIFICATE'));assert.ok(!JSON.stringify(directSource).includes(directTarget.selfRelay.keyPEM));assert.ok(!unrelated.routes.some(r=>directTunnel.routeIds.includes(r.id)));assert.ok(!unrelated.nodes.some(n=>n.token===directSource.relays.find(r=>r.id==='international').brokerToken));
 const freshDirect=await(await request('/tunnel/api/state','GET',headers)).json();assert.ok(!JSON.stringify(freshDirect).includes('PRIVATE KEY')&&!JSON.stringify(freshDirect).includes('carrier'));
 assert.equal((await request('/tunnel/api/tunnels/'+directTunnel.id,'PATCH',headers,{enabled:false})).status,200);assert.equal((await(await sync(international)).json()).selfRelay,undefined,'all paused direct routes withdraw endpoint listener');
 assert.equal((await request('/tunnel/api/tunnels/'+directTunnel.id,'DELETE',headers,{})).status,200);
 const beforeBadDirect=JSON.parse(fs.readFileSync(path.join(dir,'state.json'),'utf8'));assert.equal((await request('/tunnel/api/tunnels','POST',headers,{name:'Bad two endpoint reverse',mode:'bidirectional',source:'mainland',target:'international',relayIds:[],listenPort:15720,targetPort:16720,reverseListenPort:999})).status,400);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir,'state.json'),'utf8')),beforeBadDirect,'failed reverse preserves endpoint carrier profile and state');
 const olderPeer=await enroll(relay2.node.id);await request('/transit-node/sync','POST',{'X-Node-ID':olderPeer.id,Authorization:'Bearer '+olderPeer.token,'Content-Type':'application/json'},{revision:chainState.version,capabilities:{routeProbe:1}});assert.ok(!(await(await sync(relay)).json()).routes.some(r=>chainTunnel.routeIds.includes(r.id)),'downgrading one peer withdraws the whole chain');assert.ok((await(await sync(relay)).json()).routes.some(r=>r.name==='Scope test'),'legacy routes remain available');
 const beforeInvalid=await(await request('/tunnel/api/state','GET',headers)).json();assert.equal((await request('/tunnel/api/tunnels/'+chainTunnel.id,'PATCH',headers,{relayIds:['relay-hk','relay-hk']})).status,400);const afterInvalid=await(await request('/tunnel/api/state','GET',headers)).json();assert.deepEqual(afterInvalid.routes,beforeInvalid.routes);assert.equal(afterInvalid.version,beforeInvalid.version);
 assert.equal((await request('/tunnel/api/nodes/'+relay2.node.id,'DELETE',headers,{})).status,409);
 await request('/transit-node/sync','POST',{'X-Node-ID':mainland.id,Authorization:'Bearer '+mainland.token,'Content-Type':'application/json'},{revision:afterInvalid.version,ports:{complete:true,tcp:[18600,18601]},listeners:[testRoute.id],listenerErrors:{[testRoute.id]:'port-in-use',foreign:'port-in-use'}});
 const available=await request('/tunnel/api/ports/available?nodeId=mainland&preferred=18600','GET',headers);assert.equal(available.status,200);assert.deepEqual((await available.json()).port,18602);
 assert.equal((await request('/tunnel/api/ports/available?nodeId=mainland&preferred=22','GET',headers)).status,400);
 const occupied=await request('/tunnel/api/tunnels','POST',headers,{name:'External port conflict',mode:'single',source:'mainland',target:'international',relayIds:['relay-hk'],listenPort:18600,targetPort:5081});assert.equal(occupied.status,409);assert.match((await occupied.json()).error,/已有程序监听/);
 const portStatus=(await(await request('/tunnel/api/state','GET',headers)).json());assert.equal(portStatus.routes.find(r=>r.id===testRoute.id).listenError,'port-in-use');assert.ok(!JSON.stringify(portStatus).includes('foreign'));
 const serviceAlreadyRunning=await request('/tunnel/api/tunnels','POST',headers,{name:'Use running business port',mode:'single',source:'international',target:'mainland',relayIds:['relay-hk'],listenPort:18800,targetPort:18600});assert.equal(serviceAlreadyRunning.status,201,'occupied destination service port is intentional, not a listener collision');
 const credentials={username:'another-name',password:'invalid'};assert.equal((await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},credentials)).status,401);const blocked=await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},credentials);assert.equal(blocked.status,429);assert.equal(blocked.headers.get('retry-after'),'2');assert.equal((await request('/tunnel/api/login','POST',{'Content-Type':'application/json'},{username:'boundary-admin',password})).status,429);
 }finally{await new Promise(resolve=>{child.once('exit',resolve);child.kill();});fs.rmSync(dir,{recursive:true,force:true});}
});
