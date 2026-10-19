'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),manager=require('../deploy/tunnel-control/node-installations.cjs');
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ct-installs-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const releaseDir=path.join(dir,'releases');fs.mkdirSync(releaseDir);
 const binary=Buffer.from('fixture release'),file='chitanda-transit-linux-amd64';fs.writeFileSync(path.join(releaseDir,file),binary);fs.writeFileSync(path.join(releaseDir,'manifest.json'),JSON.stringify({version:'2.7.2',assets:{'linux-amd64':{file,sha256:crypto.createHash('sha256').update(binary).digest('hex'),size:binary.length}}}));
 const state={nodes:[{id:'node-fixture',name:'测试节点',token:'a'.repeat(64)}],relays:[]};let time=Date.now();const opts={dataDir:dir,releaseDir,getState:()=>state,enrollment:n=>({id:n.id,token:n.token,role:'agent',controller:'https://controller.example.com',controllerAddress:'8.8.8.8:443',ca:'PUBLIC CA FIXTURE'}),audit:()=>{},now:()=>time};
 const m=manager(opts);return {m,dir,releaseDir,state,opts,advance:ms=>time+=ms,ticket:info=>info.commands.install.match(/--ticket '([a-f0-9]{64})'/)[1]};
}
test('short-lived installation leases bind to one node and first server, survive restart, and never persist raw secrets',t=>{
 const f=fixture(t),info=f.m.issue('node-fixture'),ticket=f.ticket(info);assert.equal(info.available,true);assert.match(info.commands.install,/^bash <\(curl -fsSL /);assert.match(info.commands.install,/\/install\.sh/);assert.match(info.commands.installDirect,/--resolve/);assert.match(info.commands.installGithub,/raw\.githubusercontent\.com/);assert.ok(!info.commands.install.includes(info.config.token));
 assert.ok(!fs.readFileSync(path.join(f.dir,'node-installations.json'),'utf8').includes(ticket));assert.ok(!fs.readFileSync(path.join(f.dir,'node-installations.json'),'utf8').includes(info.config.token));
 assert.equal(f.m.claim({ticket},'9.9.9.9').config.id,'node-fixture');assert.equal(manager(f.opts).claim({ticket},'9.9.9.9').config.id,'node-fixture');
 assert.throws(()=>f.m.claim({ticket},'1.1.1.1'),e=>e.status===401);f.advance(15*60000+1);assert.throws(()=>f.m.claim({ticket},'9.9.9.9'),e=>e.status===401);
});
test('deleting or rotating a node invalidates its installation lease',t=>{
 const f=fixture(t),ticket=f.ticket(f.m.issue('node-fixture'));f.state.nodes[0].token='b'.repeat(64);assert.throws(()=>f.m.claim({ticket},'9.9.9.9'),e=>e.status===401);
 const other=f.ticket(f.m.issue('node-fixture'));f.state.nodes=[];assert.throws(()=>f.m.claim({ticket:other},'9.9.9.9'),e=>e.status===401);
});
test('missing or invalid releases cannot provide unsafe paths, while advanced configuration remains available',t=>{
 const f=fixture(t);assert.equal(f.m.asset('linux-amd64').size,15);assert.throws(()=>f.m.asset('../../config.json'),e=>e.status===404);
 fs.writeFileSync(path.join(f.releaseDir,'manifest.json'),JSON.stringify({version:'2.7.2',assets:{'linux-amd64':{file:'../../config.json',sha256:'f'.repeat(64),size:10}}}));assert.throws(()=>f.m.release(),e=>e.status===503);
 assert.equal(f.m.issue('node-fixture').available,false);assert.equal(f.m.issue('node-fixture').config.id,'node-fixture');
});
test('invalid enrollment attempts are bounded and do not change node identities',t=>{
 const f=fixture(t),before=structuredClone(f.state);for(let i=0;i<12;i++)assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===401);
 assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===429);assert.deepEqual(f.state,before);f.advance(61000);assert.throws(()=>f.m.claim({ticket:'bad'},'9.9.9.9'),e=>e.status===401);
});
