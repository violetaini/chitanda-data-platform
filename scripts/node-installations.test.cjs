'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),manager=require('../deploy/tunnel-control/node-installations.cjs');
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-installs-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const releaseDir=path.join(dir,'releases');fs.mkdirSync(releaseDir);
 const binary=Buffer.from('fixture release'),file='chitanda-transit-linux-amd64';fs.writeFileSync(path.join(releaseDir,file),binary);fs.writeFileSync(path.join(releaseDir,'manifest.json'),JSON.stringify({version:'2.7.2',assets:{'linux-amd64':{file,sha256:crypto.createHash('sha256').update(binary).digest('hex'),size:binary.length}}}));
 const state={nodes:[{id:'node-fixture',name:'测试节点',token:'a'.repeat(64)}],relays:[]};let time=Date.now();const opts={dataDir:dir,releaseDir,getState:()=>state,getReport:()=>({online:true}),enrollment:n=>({id:n.id,token:n.token,role:'agent',controller:'https://controller.example.com',controllerAddress:'8.8.8.8:443',ca:'PUBLIC CA FIXTURE'}),audit:()=>{},now:()=>time};
 const m=manager(opts);return {m,dir,releaseDir,state,opts,advance:ms=>time+=ms,ticket:info=>info.commands.github.match(/--ticket '([a-f0-9]{64})'/)[1]};
}
test('short-lived installation leases bind to one node and first server, survive restart, and never persist raw secrets',t=>{
 const f=fixture(t),info=f.m.issue('node-fixture'),ticket=f.ticket(info);assert.equal(info.available,true);assert.match(info.commands.github,/^CT_SOURCE=/);assert.match(info.commands.github,/node-bootstrap\.sh/);assert.match(info.commands.origin,/--resolve/);assert.match(info.commands.github,/raw\.githubusercontent\.com/);assert.ok(!info.commands.github.includes(f.state.nodes[0].token));assert.ok(info.commands.github.length<700);assert.notEqual(info.commands.github,info.commands.origin);assert.match(info.commands.origin,/^CT_SOURCE='https:\/\/controller\.example\.com\/install\.sh'/);assert.match(info.compatCommands.github,/^sh -c /);assert.ok(info.compatCommands.github.length>info.commands.github.length*4);assert.notEqual(info.compatCommands.github,info.compatCommands.origin);
 assert.ok(!fs.readFileSync(path.join(f.dir,'node-installations.json'),'utf8').includes(ticket));assert.ok(!fs.readFileSync(path.join(f.dir,'node-installations.json'),'utf8').includes(f.state.nodes[0].token));
 assert.equal(f.m.claim({ticket},'9.9.9.9').config.id,'node-fixture');assert.equal(manager(f.opts).claim({ticket},'9.9.9.9').config.id,'node-fixture');
 assert.throws(()=>f.m.claim({ticket},'1.1.1.1'),e=>e.status===401);f.advance(15*60000+1);assert.throws(()=>f.m.claim({ticket},'9.9.9.9'),e=>e.status===401);
});
test('deleting or rotating a node invalidates its installation lease',t=>{
 const f=fixture(t),ticket=f.ticket(f.m.issue('node-fixture'));f.state.nodes[0].token='b'.repeat(64);assert.throws(()=>f.m.claim({ticket},'9.9.9.9'),e=>e.status===401);
 const other=f.ticket(f.m.issue('node-fixture'));f.state.nodes=[];assert.throws(()=>f.m.claim({ticket:other},'9.9.9.9'),e=>e.status===401);
});
test('missing or invalid releases cannot provide unsafe paths, without preventing node selection',t=>{
 const f=fixture(t);assert.equal(f.m.asset('linux-amd64').size,15);assert.throws(()=>f.m.asset('../../config.json'),e=>e.status===404);
 fs.writeFileSync(path.join(f.releaseDir,'manifest.json'),JSON.stringify({version:'2.7.2',assets:{'linux-amd64':{file:'../../config.json',sha256:'f'.repeat(64),size:10}}}));assert.throws(()=>f.m.release(),e=>e.status===503);
 assert.equal(f.m.issue('node-fixture').available,false);assert.equal(f.m.issue('node-fixture').nodeId,'node-fixture');
});
test('invalid enrollment attempts are bounded and do not change node identities',t=>{
 const f=fixture(t),before=structuredClone(f.state);for(let i=0;i<12;i++)assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===401);
 assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===429);assert.deepEqual(f.state,before);f.advance(61000);assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===401);
});


test('installed state survives manager restart and does not issue installation credentials for uninstall',t=>{
 const f=fixture(t);f.state.nodes[0].installation={status:'installed',installedAt:new Date().toISOString()};
 const info=manager(f.opts).issue('node-fixture');assert.equal(info.action,'uninstall');assert.equal(info.expiresAt,null);assert.equal(info.installed,true);assert.match(info.commands.github,/ uninstall$/);assert.match(info.commands.origin,/--resolve/);assert.ok(!JSON.stringify(info).includes(f.state.nodes[0].token));assert.ok(!info.commands.github.includes('--ticket'));
 f.state.nodes[0].installation.status='uninstalled';assert.equal(manager(f.opts).issue('node-fixture').action,'install');
});


test('offline or explicitly requested reinstall returns a lease for the original identity without changing installed state',t=>{
 const f=fixture(t);f.state.nodes[0].installation={status:'installed',installedAt:new Date().toISOString()};const before=structuredClone(f.state);
 const offline=manager({...f.opts,getReport:()=>({online:false})}),info=offline.issue('node-fixture');assert.equal(info.installed,true);assert.equal(info.online,false);assert.equal(info.action,'install');assert.match(info.commands.github,/--ticket/);assert.equal(offline.claim({ticket:f.ticket(info)},'9.9.9.9').config.token,f.state.nodes[0].token);assert.deepEqual(f.state,before);
 const online=manager(f.opts).issue('node-fixture','install');assert.equal(online.action,'install');assert.equal(online.online,true);assert.match(online.commands.origin,/--ticket/);assert.equal(offline.issue('node-fixture','uninstall').action,'uninstall');assert.throws(()=>offline.issue('node-fixture','unknown'),e=>e.status===400);
});


test('release includes only fixed installer metadata and controller update policy',t=>{const f=fixture(t);f.state.settings={nodeUpdates:{enabled:false,intervalSeconds:600,failureCooldownSeconds:3600}};const r=f.m.release();assert.equal(r.installer.url,'/transit-node/install.sh');assert.match(r.installer.sha256,/^[a-f0-9]{64}$/);assert.equal(r.updatePolicy.enabled,false);assert.equal(r.updatePolicy.intervalSeconds,600);});
