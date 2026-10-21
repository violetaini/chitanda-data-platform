'use strict';
const net=require('node:net');
module.exports=function(env=process.env){
 const mode=env.CT_ACCESS_MODE||'allowlist';if(!['allowlist','subnet'].includes(mode))throw Error('Invalid source access mode');
 const allowed=new Set((env.CT_ALLOWED_IPS||'123.119.187.76,127.0.0.1,::1').split(',').map(v=>v.trim()).filter(Boolean));
 const except=new Set((env.CT_SOURCE_EXCEPTIONS||'127.0.0.1,::1').split(',').map(v=>v.trim()).filter(Boolean)),subnets=(env.CT_BLOCKED_SUBNETS||'').split(',').map(v=>v.trim()).filter(Boolean),block=new net.BlockList();
 for(const subnet of subnets){const [ip,bits]=subnet.split('/'),family=net.isIP(ip);if(!family||!/^\d+$/.test(bits||'')||Number(bits)>(family===4?32:128))throw Error('Invalid blocked subnet');block.addSubnet(ip,Number(bits),family===4?'ipv4':'ipv6');}
 if(mode==='subnet'&&!subnets.length)throw Error('Blocked subnets must be explicitly configured');
 function permits(value){const ip=String(value||'').replace(/^::ffff:/,'');const family=net.isIP(ip);if(!family)return false;if(mode==='allowlist')return allowed.has(ip);return except.has(ip)||!block.check(ip,family===4?'ipv4':'ipv6');}
 return {permits,summary:()=>({mode,allowedIPs:mode==='allowlist'?[...allowed]:[],blockedSubnets:mode==='subnet'?subnets:[],exceptions:mode==='subnet'?[...except]:[]})};
};
