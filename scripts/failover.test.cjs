'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const f=require('../deploy/tunnel-control/failover.cjs'),http=require('../deploy/tunnel-control/http-access.cjs');
const root={id:'r',name:'双向',source:'cn',target:'hk',relayIds:['hk'],transport:'h2',serverName:'data.example.com',listenPort:15082,targetPort:16082,enabled:true};
const validate=r=>({...r,relayIds:r.relayIds.length?r.relayIds:['hk']});
const backup={id:'backup-0123456789abcdef',name:'优化',relayIds:['opt','hk']};
test('backup profiles expand without changing logical ingress or endpoint',()=>{
 const p=f.normalize([backup],root,validate);const [a,b]=f.expand({...root,backupPaths:p});
 assert.equal(a.listenPort,15082);assert.equal(a.id,'r');assert.equal(b.listenPort,0);assert.equal(b.parentRouteId,'r');assert.equal(b.targetPort,16082);assert.equal(b.target,'hk');assert.deepEqual(a.fallbackRouteIds,[b.id]);assert.deepEqual(f.nodeIds({...root,backupPaths:p}),['cn','hk','opt']);
});
test('reject repeated, injected and excessive backups; IDs remain stable',()=>{
 assert.throws(()=>f.normalize([{...backup,relayIds:['hk']}],root,validate));
 assert.throws(()=>f.normalize([backup,backup],root,validate));
 assert.throws(()=>f.normalize([{...backup,target:'evil'}],root,validate));
 assert.throws(()=>f.normalize([{...backup,direct:'false'}],root,validate));
 assert.throws(()=>f.normalize(Array(9).fill(backup),root,validate));assert.throws(()=>f.normalize(null,root,validate));
 assert.equal(f.normalize([backup],root,validate)[0].id,backup.id);
});
test('health reports cannot forge unrelated route paths or stale healthy probes',()=>{
 const r={...root,backupPaths:f.normalize([backup],root,validate)},now=Date.now(),id='r~'+backup.id;
 const s={routes:[r]};const got=f.report(s,'cn',{r:{activePathId:'forged',switches:4,paths:{r:{healthy:true,checkedAt:now-31000},[id]:{healthy:true,checkedAt:now},evil:{healthy:true,checkedAt:now}}}},now);
 assert.equal(got.r.activePathId,'r');assert.equal(got.r.paths.r.healthy,false);assert.equal(got.r.paths[id].healthy,true);assert.equal(Object.keys(got.r.paths).length,2);assert.deepEqual(f.report(s,'opt',{r:{}},now),{});
});
test('reverse tunnel backup keeps identity and reverses ordered relays',()=>{
 const model=require('../deploy/tunnel-control/tunnels.cjs');const s={routes:[],nodes:[],relays:[],tunnels:[],domains:[],version:1};let i=0;
 const m=model({getState:()=>s,validateRoute:(v,id)=>({...v,id:id||'r'+(++i)}),ensureCertificates:()=>{},audit:()=>{}});
 const t=m.write({...root,mode:'bidirectional',backupPaths:[backup]});const [a,b]=t.routeIds.map(id=>s.routes.find(r=>r.id===id));
 assert.equal(a.backupPaths[0].id,b.backupPaths[0].id);assert.deepEqual(b.backupPaths[0].relayIds,['hk','opt']);assert.equal(b.source,a.target);
});
test('reverse backup retains direct endpoint carrier mode',()=>{
 const model=require('../deploy/tunnel-control/tunnels.cjs'),s={routes:[],nodes:[],relays:[],tunnels:[],domains:[],version:1};let i=0;
 const m=model({getState:()=>s,validateRoute:(v,id)=>({...v,id:id||'r'+(++i)}),ensureCertificates:()=>{},audit:()=>{}});
 m.write({...root,mode:'bidirectional',backupPaths:[{...backup,direct:true,relayIds:['hk']}]});assert.equal(s.routes[1].backupPaths[0].direct,true);
});
