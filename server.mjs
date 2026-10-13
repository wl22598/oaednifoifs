import http from 'node:http';
import https from 'node:https';
import { gunzipSync, inflateSync, brotliDecompressSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

const FIXED_UPSTREAM = 'https://daily-study-atlas.swiftridge33.chatgpt.site';
const HOP = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const LIMIT = 16 * 1024 * 1024;
function clean(headers) {
  const blocked = new Set([...HOP, ...String(headers.connection || '').split(',').map(x => x.trim().toLowerCase())]);
  return Object.fromEntries(Object.entries(headers).filter(([k]) => !blocked.has(k.toLowerCase())));
}
function publicOrigin(value, testing) {
  const u = new URL(value);
  if ((!testing && u.protocol !== 'https:') || !['http:','https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('PUBLIC_URL must be a bare HTTPS origin');
  return u.origin;
}
export function createProxy({publicUrl, upstream = FIXED_UPSTREAM, testing = false}) {
  if (!testing && upstream !== FIXED_UPSTREAM) throw new Error('Upstream is fixed');
  const base = new URL(upstream);
  const origin = publicOrigin(publicUrl, testing);
  const rewrite = value => value.replaceAll(base.origin, origin).replaceAll(base.origin.replaceAll('/', '\\/'), origin.replaceAll('/', '\\/'));
  const fail = (res, code, message) => { if (res.headersSent) return res.destroy(); res.writeHead(code, {'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}); res.end(message); };
  const server = http.createServer(async (req, res) => {
    if (req.url === '/__proxy_health') { res.writeHead(200, {'content-type':'application/json','cache-control':'no-store'}); return res.end('{"status":"proxy-process-ready","upstreamVerified":false}'); }
    if (!req.url?.startsWith('/') || req.url.startsWith('//') || req.url.includes('\\')) return fail(res, 400, 'Invalid request path');
    if (!['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(req.method)) return fail(res, 405, 'Method not supported');
    if (!['GET','HEAD','OPTIONS'].includes(req.method) && req.headers.origin && req.headers.origin !== origin) return fail(res, 403, 'Cross-origin write rejected');
    const target = new URL(req.url, base);
    if (target.origin !== base.origin) return fail(res, 400, 'Invalid target');
    const body = [];
    let size = 0;
    try { for await (const chunk of req) { size += chunk.length; if (size > 2 * 1024 * 1024) return fail(res, 413, 'Request body too large'); body.push(chunk); } } catch { return fail(res, 400, 'Incomplete request'); }
    const headers = clean(req.headers);
    for (const name of Object.keys(headers)) if (name === 'host' || name === 'forwarded' || name.startsWith('x-forwarded-')) delete headers[name];
    headers.host = base.host;
    headers['accept-encoding'] = 'identity';
    if (headers.origin === origin) headers.origin = base.origin;
    if (headers.referer) { try { const r = new URL(headers.referer); if (r.origin === origin) headers.referer = base.origin + r.pathname + r.search; } catch { delete headers.referer; } }
    if (size) headers['content-length'] = String(size);
    const outgoing = (base.protocol === 'https:' ? https : http).request(target, {method:req.method,headers}, response => {
      const out = clean(response.headers);
      delete out['access-control-allow-origin']; delete out['access-control-allow-credentials'];
      if (out.location) { try { const loc = new URL(out.location, base); if (loc.origin === base.origin) out.location = origin + loc.pathname + loc.search + loc.hash; } catch {} }
      for (const key of ['content-security-policy','content-security-policy-report-only']) if (out[key]) out[key] = rewrite(out[key]);
      if (out['set-cookie']) out['set-cookie'] = out['set-cookie'].flatMap(cookie => {
        const d = cookie.match(/;\s*Domain=([^;]+)/i);
        if (!d) return [cookie];
        const domain = d[1].trim().replace(/^\./,'').toLowerCase();
        if (base.hostname !== domain && !base.hostname.endsWith('.' + domain)) return [];
        return [cookie.replace(/;\s*Domain=[^;]+/i,'')];
      });
      const textual = /(?:text\/html|text\/css|javascript|application\/json|text\/plain)/i.test(String(out['content-type'] || ''));
      if (textual || out['set-cookie'] || target.pathname.startsWith('/api/') || target.pathname.startsWith('/login') || target.pathname.startsWith('/admin')) out['cache-control'] = 'private, no-store';
      if (!textual || req.method === 'HEAD' || [204,304].includes(response.statusCode)) {
        res.writeHead(response.statusCode, out); response.on('error', () => res.destroy()); response.pipe(res); return;
      }
      const chunks = []; let total = 0;
      response.on('data', chunk => { total += chunk.length; if (total > LIMIT) { response.destroy(); fail(res, 502, 'Upstream text exceeds proxy limit'); } else chunks.push(chunk); });
      response.on('error', () => fail(res, 502, 'Upstream response interrupted'));
      response.on('end', () => {
        if (res.destroyed || res.writableEnded) return;
        try {
          let data = Buffer.concat(chunks); const encoding = String(out['content-encoding'] || '').toLowerCase();
          const decompress = {gzip:gunzipSync, deflate:inflateSync, br:brotliDecompressSync}[encoding];
          if (decompress) data = decompress(data, {maxOutputLength:LIMIT});
          else if (encoding && encoding !== 'identity') return fail(res, 502, 'Unsupported upstream encoding');
          data = Buffer.from(rewrite(data.toString('utf8')));
          delete out['content-encoding']; delete out.etag; delete out['content-md5']; delete out['content-length'];
          out['content-length'] = String(data.length); res.writeHead(response.statusCode, out); res.end(data);
        } catch { fail(res, 502, 'Could not process upstream response'); }
      });
    });
    outgoing.setTimeout(30000, () => outgoing.destroy(new Error('timeout')));
    outgoing.on('error', () => fail(res, 502, 'Could not reach the learning site; no access restrictions were bypassed.'));
    res.on('close', () => { if (!res.writableEnded) outgoing.destroy(); });
    outgoing.end(Buffer.concat(body));
  });
  server.on('upgrade', (req, socket) => { socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n'); });
  server.requestTimeout = 60000; server.headersTimeout = 15000;
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const url = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL;
  if (!url) throw new Error('Set PUBLIC_URL or deploy on Render with RENDER_EXTERNAL_URL');
  const server = createProxy({publicUrl:url});
  server.listen(Number(process.env.PORT || 10000),'0.0.0.0',() => console.log('Learning-site proxy ready; upstream and mainland access still require verification.'));
  process.on('SIGTERM', () => server.close());
}
