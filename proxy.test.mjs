import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { gzipSync } from 'node:zlib';
import { once } from 'node:events';
import { createProxy } from './server.mjs';

test('fixed-site forwarding: sessions, origins, redirects, assets and block responses', async () => {
  let upstreamOrigin;
  const received = [];
  const upstream = http.createServer(async (req,res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    received.push({url:req.url,headers:req.headers,body});
    if (req.url === '/login') { res.writeHead(302, {location:upstreamOrigin + '/learn/', 'set-cookie':['learner=abc; Domain=127.0.0.1; Path=/; HttpOnly; Secure; SameSite=Lax','prefs=dark; Path=/; SameSite=Lax']}); return res.end(); }
    if (req.url === '/external') { res.writeHead(302,{location:'https://example.com/source'}); return res.end(); }
    if (req.url === '/blocked') { res.writeHead(403,{'content-type':'text/html'}); return res.end('Cloudflare blocked'); }
    if (req.url === '/binary') { res.writeHead(200,{'content-type':'application/pdf'}); return res.end(Buffer.from([0,255,64,0,128])); }
    if (req.url === '/compressed') { res.writeHead(200,{'content-type':'text/html','content-encoding':'gzip'}); return res.end(gzipSync('<a href="' + upstreamOrigin + '/learn/">Course</a>')); }
    res.writeHead(200,{'content-type':'application/json'}); res.end(JSON.stringify({url:req.url,body,origin:req.headers.origin,cookie:req.headers.cookie,referer:req.headers.referer,link:upstreamOrigin + '/learn/'}));
  });
  upstream.listen(0,'127.0.0.1'); await once(upstream,'listening');
  upstreamOrigin = 'http://127.0.0.1:' + upstream.address().port;
  const proxy = createProxy({upstream:upstreamOrigin, publicUrl:'https://zhixu-test.example',testing:true});
  proxy.listen(0,'127.0.0.1'); await once(proxy,'listening');
  const root = 'http://127.0.0.1:' + proxy.address().port;
  try {
    const health = await fetch(root + '/__proxy_health'); assert.equal((await health.json()).upstreamVerified,false); assert.equal(received.length,0);
    const login = await fetch(root + '/login',{redirect:'manual'}); assert.equal(login.status,302); assert.equal(login.headers.get('location'),'https://zhixu-test.example/learn/');
    const cookies = login.headers.getSetCookie(); assert.equal(cookies.length,2); assert.ok(cookies.every(c=>!c.includes('Domain='))); assert.match(cookies[0],/HttpOnly; Secure; SameSite=Lax/); assert.match(login.headers.get('cache-control'),/no-store/);
    const write = await fetch(root + '/api/progress?course=cfa',{method:'POST',headers:{origin:'https://zhixu-test.example',referer:'https://zhixu-test.example/learn/',cookie:'learner=abc','content-type':'application/json','x-forwarded-host':'evil.test'},body:'{"completed":1}'});
    const saved = await write.json(); assert.equal(saved.body,'{"completed":1}'); assert.equal(saved.cookie,'learner=abc'); assert.equal(saved.origin,'https://zhixu-test.example');
    const entry = received.at(-1); assert.equal(entry.headers.origin,upstreamOrigin); assert.equal(entry.headers.referer,upstreamOrigin + '/learn/'); assert.equal(entry.headers['x-forwarded-host'],undefined); assert.equal(entry.url,'/api/progress?course=cfa');
    const before = received.length;
    assert.equal((await fetch(root + '/api/progress',{method:'POST',headers:{origin:'https://evil.test'},body:'bad'})).status,403); assert.equal(received.length,before);
    const blocked = await fetch(root + '/blocked'); assert.equal(blocked.status,403); assert.equal(await blocked.text(),'Cloudflare blocked');
    const external = await fetch(root + '/external',{redirect:'manual'}); assert.equal(external.headers.get('location'),'https://example.com/source');
    const compressed = await fetch(root + '/compressed'); assert.equal(compressed.headers.get('content-encoding'),null); assert.match(await compressed.text(),/https:\/\/zhixu-test.example\/learn\//);
    assert.deepEqual(Buffer.from(await (await fetch(root + '/binary')).arrayBuffer()),Buffer.from([0,255,64,0,128]));
    const head = await fetch(root + '/binary',{method:'HEAD'}); assert.equal((await head.arrayBuffer()).byteLength,0);
    await new Promise((resolve,reject) => { const request=http.request(root,{path:'//example.com/private'},response=>{ assert.equal(response.statusCode,400); response.resume(); response.on('end',resolve); }); request.on('error',reject); request.end(); });
    assert.throws(()=>createProxy({upstream:'https://example.com',publicUrl:'https://proxy.example'}),/fixed/);
    assert.throws(()=>createProxy({publicUrl:'http://proxy.example'}),/HTTPS/);
  } finally { proxy.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([new Promise(r=>proxy.close(r)),new Promise(r=>upstream.close(r))]); }
});
