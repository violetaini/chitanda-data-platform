'use strict';
const crypto=require('node:crypto');
// A direct path can terminate on an ordinary endpoint. Its purpose and identity
// remain unchanged; only this scoped protocol listener is provisioned on demand.
const all=state=>[...state.relays,...state.nodes.filter(n=>n.carrier).map(n=>({...n.carrier,id:n.id,host:n.host}))];
function ensure(node,serverName){
 node.carrier||={port:18443,streamPort:11323,serverName,path:'/api/v1/chitanda-bridge',psk:crypto.randomBytes(32).toString('base64')};
 return {...node.carrier,id:node.id,host:node.host};
}
function certificates(state,ensureCertificate){
 for(const node of [...state.relays,...state.nodes.filter(n=>n.carrier)]){
  const profile=node.carrier?{...node.carrier,id:node.id,host:node.host}:node;
  ensureCertificate(profile);
  if(node.carrier){const {id,host,...privateProfile}=profile;node.carrier=privateProfile;}
 }
}
module.exports={all,ensure,certificates};
