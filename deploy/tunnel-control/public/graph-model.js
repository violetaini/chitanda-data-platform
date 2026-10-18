'use strict';
(function(root){
 const finite=n=>Number.isFinite(Number(n))&&Number(n)>=0?Number(n):0;
 function aggregateGraph(topology){
  const nodes=(topology?.nodes||[]).map(n=>({...n})),ids=new Set(nodes.map(n=>n.id)),edges=new Map();
  for(const edge of topology?.edges||[]){if(!ids.has(edge.source)||!ids.has(edge.target)||edge.source===edge.target)continue;const [a,b]=[edge.source,edge.target].sort(),key=[edge.kind||'data',a,b].join('|');let item=edges.get(key);if(!item){item={id:key,source:a,target:b,kind:edge.kind||'data',directions:[],routes:[],protocols:[],enabled:false,ready:false};edges.set(key,item);}if(!item.directions.includes(edge.source+'>'+edge.target))item.directions.push(edge.source+'>'+edge.target);if(edge.routeId&&!item.routes.some(r=>r.id===edge.routeId))item.routes.push({id:edge.routeId,name:edge.name});if(edge.transport&&!item.protocols.includes(edge.transport))item.protocols.push(edge.transport);item.enabled||=edge.enabled===true;item.ready||=edge.enabled===true&&edge.ready===true;}
  return {nodes,edges:[...edges.values()]};
 }
 function layoutGraph(model){
  const origins=model.nodes.filter(n=>n.kind==='origin');
  if(origins.length){
   const controllers=model.nodes.filter(n=>n.kind==='control'),agents=model.nodes.filter(n=>!['origin','control','relay'].includes(n.kind)),relays=model.nodes.filter(n=>n.kind==='relay'),relayIds=new Set(relays.map(n=>n.id));
   const sides=[[],[]];for(const n of origins)sides[relayIds.has(n.endpoint)?1:0].push(n);
   const lanes=[sides[0],agents,relays,sides[1]],rows=Math.max(1,...lanes.map(l=>l.length)),height=Math.max(326,196+(rows-1)*136+104),nodes=[];
   lanes.forEach((lane,col)=>lane.sort((a,b)=>a.id.localeCompare(b.id)).forEach((n,i)=>nodes.push({...n,x:138+col*312,y:216+(rows-1)*68+(i-(lane.length-1)/2)*136,width:224,height:104,lane:col})));
   controllers.forEach((n,i)=>nodes.push({...n,x:606,y:42+i*64,width:204,height:48,lane:'control'}));
   return {nodes,edges:model.edges,width:1212,height};
  }
  // Roles and current edges determine the lanes; no node identity or server address is fixed.
  const sorted=[...model.nodes].sort((a,b)=>(a.name||a.id).localeCompare(b.name||b.id,'zh-CN')||a.id.localeCompare(b.id)),links=new Map(sorted.map(n=>[n.id,[]]));
  for(const e of model.edges.filter(e=>e.kind!=='control')){links.get(e.source)?.push(e.target);links.get(e.target)?.push(e.source);}
  const controllers=sorted.filter(n=>n.kind==='control'),relays=sorted.filter(n=>n.kind==='relay'),agents=sorted.filter(n=>n.kind!=='control'&&n.kind!=='relay'),left=[],right=[],detached=[];
  for(const n of agents){if(!links.get(n.id).length){detached.push(n);continue;}const first=model.edges.find(e=>e.kind!=='control'&&(e.source===n.id||e.target===n.id)),direction=first?.directions?.[0],outgoing=direction?.startsWith(n.id+'>');(direction?(outgoing?left:right):(left.length<=right.length?left:right)).push(n);}
  const relayOrder=new Map(relays.map((n,i)=>[n.id,i])),rank=n=>{const peers=links.get(n.id).filter(id=>relayOrder.has(id));return peers.length?peers.reduce((sum,id)=>sum+relayOrder.get(id),0)/peers.length:0;};
  for(const lane of [left,right])lane.sort((a,b)=>rank(a)-rank(b));
  const cardWidth=224,cardHeight=104,width=900,nodes=[],lanes=[left,relays,right],rows=Math.max(1,...lanes.map(l=>l.length)),bodyTop=164,bodyHeight=(rows-1)*136+cardHeight;
  controllers.forEach((n,i)=>nodes.push({...n,x:width/2,y:42+i*64,width:204,height:48,lane:'control'}));
  const offset=Math.max(0,controllers.length-1)*64;
  lanes.forEach((lane,column)=>lane.forEach((n,i)=>nodes.push({...n,x:138+column*312,y:bodyTop+offset+cardHeight/2+(bodyHeight-cardHeight)/2+(i-(lane.length-1)/2)*136,width:cardWidth,height:cardHeight,lane:column})));
  const detachedTop=bodyTop+offset+bodyHeight+76;
  detached.forEach((n,i)=>nodes.push({...n,x:138+i%3*312,y:detachedTop+Math.floor(i/3)*136+cardHeight/2,width:cardWidth,height:cardHeight,lane:'unassigned'}));
  const height=Math.max(326,...nodes.map(n=>n.y+n.height/2+32));
  return {nodes,edges:model.edges,width,height,detachedTop:detached.length?detachedTop:null};
 }
 function chartModel(samples,{now=Date.now(),windowMs=300000}={}){
  const sorted=[...new Map((samples||[]).filter(p=>Number.isFinite(Number(p.at))).map(p=>[Number(p.at),p])).values()].sort((a,b)=>a.at-b.at),points=[];
  for(let i=1;i<sorted.length;i++){const a=sorted[i-1],b=sorted[i],dt=(b.at-a.at)/1000;if(b.at<now-windowMs||b.at>now)continue;const gap=dt<=0||dt>45||finite(b.rx)<finite(a.rx)||finite(b.tx)<finite(a.tx)||(b.uptime!==undefined&&a.uptime!==undefined&&finite(b.uptime)<finite(a.uptime));points.push({at:Number(b.at),rx:gap?null:(finite(b.rx)-finite(a.rx))/dt,tx:gap?null:(finite(b.tx)-finite(a.tx))/dt});}
  const peak=Math.max(1,...points.flatMap(p=>[p.rx||0,p.tx||0])),power=10**Math.floor(Math.log10(peak)),top=[1,2,2.5,5,10].map(n=>n*power).find(n=>n>=peak*1.08)||10*power,unit=top>=1048576?'MB/s':top>=1024?'KB/s':'B/s',divisor=unit==='MB/s'?1048576:unit==='KB/s'?1024:1;
  return {points,start:now-windowMs,end:now,top,unit,divisor,latest:[...points].reverse().find(p=>p.rx!==null),stale:!points.length||points.at(-1).rx===null||now-points.at(-1).at>45000};
 }
 // Monotone cubic interpolation: preserve each sample and avoid overshooting peaks/zero.
 function smoothPath(points){
  if(!points.length)return '';if(points.length===1)return `M${points[0].x},${points[0].y}`;
  const slopes=points.slice(1).map((p,i)=>(p.y-points[i].y)/(p.x-points[i].x||1)),tangents=points.map((p,i)=>i===0?slopes[0]:i===points.length-1?slopes.at(-1):slopes[i-1]*slopes[i]<=0?0:2/(1/slopes[i-1]+1/slopes[i]));
  let d=`M${points[0].x},${points[0].y}`;for(let i=1;i<points.length;i++){const a=points[i-1],b=points[i],dx=(b.x-a.x)/3;d+=`C${a.x+dx},${a.y+dx*tangents[i-1]} ${b.x-dx},${b.y-dx*tangents[i]} ${b.x},${b.y}`;}return d;
 }
 const api={aggregateGraph,layoutGraph,chartModel,smoothPath};root.PlatformGraphs=api;if(typeof module==='object')module.exports=api;
})(globalThis);
