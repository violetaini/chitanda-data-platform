'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),create=require('../deploy/tunnel-control/source-access.cjs');
test('public subnet blocks include boundaries and mapped IPv4, preserve own sources and allow residential addresses',()=>{
 const p=create({CT_ACCESS_MODE:'subnet',CT_BLOCKED_SUBNETS:'110.42.32.0/24,168.138.209.0/24',CT_SOURCE_EXCEPTIONS:'110.42.32.161,168.138.209.1,127.0.0.1,::1'});
 for(const ip of ['110.42.32.0','110.42.32.255','110.42.32.162','168.138.209.2','::ffff:168.138.209.2','invalid'])assert.equal(p.permits(ip),false,ip);
 for(const ip of ['110.42.32.161','168.138.209.1','::ffff:110.42.32.161','127.0.0.1','::1','123.119.187.76','123.122.92.15','8.8.8.8','2001:db8::1'])assert.equal(p.permits(ip),true,ip);
 assert.deepEqual(p.summary().allowedIPs,[]);assert.throws(()=>create({CT_ACCESS_MODE:'subnet'}));assert.throws(()=>create({CT_ACCESS_MODE:'typo'}));assert.throws(()=>create({CT_ACCESS_MODE:'subnet',CT_BLOCKED_SUBNETS:'1.2.3.4/33'}));
 assert.equal(create({}).permits('8.8.8.8'),false);
});
