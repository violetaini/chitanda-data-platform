'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),scheduler=require('../deploy/tunnel-control/dns-address-sync.cjs');
test('multiple tunnels sharing a changed node update independently and ignore drafts',async()=>{
 const state={nodes:[{id:'cn',host:'8.8.8.8'}],relays:[],routes:[{id:'a',source:'cn'},{id:'b',source:'cn'},{id:'draft',source:'cn'}],tunnels:[{id:'one',routeIds:['a']},{id:'two',routeIds:['b']},{id:'draft',routeIds:['draft']}],domains:[{id:'one',domain:'one.example.com',tunnelId:'one',status:'published'},{id:'two',domain:'two.example.com',tunnelId:'two',status:'published'},{id:'draft',tunnelId:'draft',status:'draft'}]};
 let time=Date.now(),calls=[],failure=false;
 const options={getState:()=>state,syncAddresses:async id=>{calls.push(id);if(failure&&id==='one')throw Error('certificate not ready');return {changes:{update:[]}};},isBusy:()=>false,save:()=>{},audit:()=>{},now:()=>time};
 let m=scheduler(options);await m.tick();assert.deepEqual(calls,['one','two']);await m.tick();assert.equal(calls.length,2);
 state.nodes[0].host='9.9.9.9';assert.equal(scheduler.summary(state,state.domains[0]).status,'pending');failure=true;await m.tick();assert.deepEqual(calls,['one','two','one','two']);assert.equal(scheduler.summary(state,state.domains[0]).status,'error');assert.equal(scheduler.summary(state,state.domains[1]).status,'synced');
 m=scheduler(options);await m.tick();assert.equal(calls.length,4,'retry delay survives restart');time+=30000;failure=false;await m.tick();assert.equal(calls.length,5);assert.equal(scheduler.summary(state,state.domains[0]).status,'synced');
 time+=300000;await m.tick();assert.deepEqual(calls.slice(-2),['one','two'],'periodic reconciliation resumes without IP events');
});
test('scheduler coalesces simultaneous runs and remembers only verified targets',async()=>{
 const state={nodes:[{id:'cn',host:'8.8.8.8'}],relays:[],routes:[{id:'a',source:'cn'}],tunnels:[{id:'one',routeIds:['a']}],domains:[{id:'one',domain:'one.example.com',tunnelId:'one',status:'published'}]};let release,calls=0;
 const m=scheduler({getState:()=>state,syncAddresses:()=>{calls++;return new Promise(r=>release=r);},isBusy:()=>false,save:()=>{},audit:()=>{}});
 const first=m.tick();await m.tick();assert.equal(calls,1);state.nodes[0].host='9.9.9.9';release({changes:{update:[{}]}});await first;
 assert.equal(state.domains[0].addressSync.targets[0].host,'8.8.8.8');assert.equal(scheduler.summary(state,state.domains[0]).status,'pending');
});
test('unchanged IP with a failed periodic read remains published and reports a check retry',async()=>{
 const state={nodes:[{id:'cn',host:'8.8.8.8'}],relays:[],routes:[{id:'a',source:'cn'}],tunnels:[{id:'one',routeIds:['a']}],domains:[{id:'one',domain:'one.example.com',tunnelId:'one',status:'published'}]},binding=state.domains[0];
 const verified=[{routeId:'a',nodeId:'cn',host:'8.8.8.8'}],checkedAt='2026-10-19T12:00:00Z';binding.addressSync={targets:verified,attemptedTargets:verified,checkedAt};let time=Date.parse(checkedAt)+300000,fail=true,events=[];
 const options={getState:()=>state,syncAddresses:async()=>{if(fail)throw Error('DNS temporarily unavailable');return {changes:{update:[]}};},isBusy:()=>false,save:()=>{},audit:action=>events.push(action),now:()=>time};
 await scheduler(options).tick();let view=scheduler.summary(state,binding);assert.equal(view.status,'check-error');assert.equal(view.addressChanged,false);assert.equal(view.checkedAt,checkedAt);assert.equal(binding.status,'published');assert.equal(events[0],'节点解析定期核验待重试');
 const restarted=structuredClone(state);assert.equal(scheduler.summary(restarted,restarted.domains[0]).status,'check-error');
 time+=30000;fail=false;await scheduler(options).tick();view=scheduler.summary(state,binding);assert.equal(view.status,'synced');assert.equal(view.lastError,undefined);
});
test('a first check cannot claim an IP change or invent an unchanged baseline',()=>{
 const state={nodes:[{id:'cn',host:'8.8.8.8'}],relays:[],routes:[{id:'a',source:'cn'}],tunnels:[{id:'one',routeIds:['a']}],domains:[]},binding={tunnelId:'one',status:'published'};
 assert.equal(scheduler.summary(state,binding).status,'checking');assert.equal(scheduler.summary(state,binding).addressChanged,null);
 binding.addressSync={attemptedTargets:scheduler.targets(state,binding),lastError:'unavailable'};assert.equal(scheduler.summary(state,binding).status,'check-error');assert.equal(scheduler.summary(state,binding).addressChanged,null);
});
