'use strict';
const net=require('node:net');
const blocked=new net.BlockList(),blocked6=new net.BlockList();
for(const [ip,bits]of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['192.0.0.0',24],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]])blocked.addSubnet(ip,bits,'ipv4');
blocked.addAddress('168.63.129.16','ipv4');
for(const [ip,bits]of [['::',96],['::ffff:0:0',96],['fc00::',7],['fe80::',10],['ff00::',8],['64:ff9b::',96],['2002::',16]])blocked6.addSubnet(ip,bits,'ipv6');
module.exports=ip=>{if(typeof ip!=='string')return false;const family=net.isIP(ip);return family===4?!blocked.check(ip,'ipv4'):family===6&&!blocked6.check(ip,'ipv6');};
