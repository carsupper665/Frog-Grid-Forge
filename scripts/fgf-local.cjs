// Local-only FGF integration environment. All databases, keys, credentials and
// logs live in a new ignored run directory; no existing .env is read by a backend.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'output', 'fgf-local');
const run = path.join(output, `run-${Date.now()}`);
fs.mkdirSync(run, { recursive: true });
const bin = path.join(output, 'bin'); fs.mkdirSync(bin, { recursive: true });
const base = 'http://127.0.0.1:15525';
const children = [], servers = [], mail = [];
const password = crypto.randomBytes(24).toString('base64url');
const backendEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|SystemRoot|WINDIR|USERPROFILE|TEMP|TMP|PATHEXT|COMSPEC|APPDATA|LOCALAPPDATA)$/i.test(key)));
const services = [
  { name: 'mc', dir: 'mc-server-backend', entry: '.', port: 18080, url: 'http://127.0.0.1:15173', callback: '/login/fgf/callback' },
  { name: 'trading', dir: 'trading', entry: './cmd/server', port: 18081, url: 'http://127.0.0.1:18081', callback: '/api/auth/fgf/callback' },
  { name: 'chaintrace', dir: 'chaintrace', entry: '.', port: 18082, url: 'http://127.0.0.1:15175', callback: '/login/fgf/callback' },
];
function launch(name, command, args, cwd, env) {
  const log = fs.openSync(path.join(run, `${name}.log`), 'a');
  const child = spawn(command, args, { cwd, env, windowsHide: true, stdio: ['ignore', log, log] });
  fs.closeSync(log); children.push(child);
  child.on('error', err => console.error(`${name}: ${err.message}`));
  return child;
}
function command(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, windowsHide: true, stdio: 'inherit' });
    children.push(child); child.on('error', reject); child.on('exit', code => code === 0 ? resolve() : reject(new Error(`${command} failed (${code})`)));
  });
}
async function ready(url, child, timeout = 90000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) throw new Error(`Server exited; see ${run}`);
    try { const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(1500) }); if (r.status < 500) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error(`Timeout waiting for ${url}; see ${run}`);
}
async function listen(server, port) { servers.push(server); await new Promise((resolve,reject) => { server.once('error',reject); server.listen(port,'127.0.0.1',resolve); }); }
async function mailbox() {
  await listen(net.createServer(socket => {
    socket.setTimeout(30000, () => socket.destroy());
    socket.on('error', () => {}); socket.write('220 localhost FGF test mail\r\n');
    let buffer = '', data = false, lines = [];
    socket.on('data', chunk => {
      buffer += chunk.toString(); let end;
      while ((end = buffer.indexOf('\r\n')) >= 0) {
        const line = buffer.slice(0,end); buffer = buffer.slice(end+2);
        if (data) {
          if (line !== '.') { lines.push(line.replace(/^\.\./,'.')); continue; }
          const message = lines.join('\n'); mail.push(message); fs.writeFileSync(path.join(run,'mail.json'),JSON.stringify(mail));
          data = false; lines = []; socket.write('250 accepted\r\n'); continue;
        }
        const verb = line.split(' ')[0].toUpperCase();
        if (verb === 'EHLO') socket.write('250-localhost\r\n250 AUTH PLAIN\r\n');
        else if (verb === 'AUTH') socket.write('235 authenticated\r\n');
        else if (verb === 'DATA') { data = true; socket.write('354 End with dot\r\n'); }
        else if (verb === 'QUIT') { socket.end('221 goodbye\r\n'); }
        else socket.write('250 OK\r\n');
      }
    });
  }),15527);
  await listen(http.createServer((req,res) => {
    res.setHeader('Cache-Control','no-store');
    if(req.url === '/messages') { res.setHeader('Content-Type','application/json');res.end(JSON.stringify(mail));return; }
    const links = mail.flatMap(message => message.match(/http:\/\/127\.0\.0\.1:15525\/x\/verify\?t=[A-Za-z0-9._~%+-]+/g) || []);
    res.setHeader('Content-Type','text/html; charset=utf-8');
    res.end('<!doctype html><meta charset="utf-8"><title>FGF 本機信箱</title><h1>FGF 本機驗證信箱</h1><p>收到驗證信後重新整理，在登入的同一瀏覽器點開連結。</p>'+links.map((link,i)=>`<p><a href="${link}">驗證信 ${i+1}</a></p>`).join(''));
  }),15526);
}
async function main() {
  // Refuse occupied service ports rather than reusing an unrelated process.
  for (const port of [15525,15526,15527,18080,18081,18082,15173,15175]) {
    const probe = net.createServer(); await new Promise((resolve,reject)=> { probe.once('error',reject);probe.listen(port,'127.0.0.1',()=>probe.close(resolve)); });
  }
  const exe = name => path.join(bin,name+(process.platform==='win32'?'.exe':''));
  if (!process.argv.includes('--skip-build')) {
    for (const svc of [{name:'idp',dir:'FGF-idP',entry:'.'},...services]) {
      console.log(`Building ${svc.name}...`); await command('go',['build','-o',exe(svc.name),svc.entry],path.join(root,svc.dir));
    }
  }
  await mailbox();
  const idpDir = path.join(run,'idp');fs.mkdirSync(idpDir);
  const common = { SESSION_SECRET:crypto.randomBytes(32).toString('hex'), DEBUG:'true', CREATE_ROOT_USER:'false', AUTO_UPDATE:'false', UA_FILTER:'false', GLOBAL_API_RATE_LIMIT:'1000' };
  const idp = launch('idp',exe('idp'),[],idpDir,{...backendEnv,...common,PORT:'15525',BACKEND_BASE_URL:base,COOKIE_SECURE:'false',CREATE_ROOT_USER:'true',ROOT_USER_NAME:'fgf-local',ROOT_USER_EMAIL:'fgf-local@example.test',ROOT_USER_PASSWORD:password,SMTP_SERVER:'127.0.0.1',SMTP_PORT:'15527',SMTP_ACCOUNT:'idp@example.test',SMTP_FROM:'idp@example.test',SMTP_TOKEN:'local-mail-only'});
  await ready(base+'/.well-known/openid-configuration',idp);
  const admin = await fetch(base+'/x/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:'fgf-local',password})});
  if(!admin.ok) throw new Error(`IDP bootstrap login: ${admin.status}`);
  const cookie = admin.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  const profile=await fetch(base+'/x/admin/me',{headers:{Cookie:cookie}}).then(r=>r.json());
  for(const svc of services) {
    const response = await fetch(base+'/x/admin/clients',{method:'POST',headers:{Cookie:cookie,'Content-Type':'application/json'},body:JSON.stringify({client_id:`fgf-${svc.name}`,name:svc.name,redirect_uris:[svc.url+svc.callback],scope:'openid profile email'})});
    if(!response.ok) throw new Error(`Client ${svc.name}: ${response.status}`);
    const client=await response.json();
    const cwd=path.join(run,svc.name);fs.mkdirSync(cwd);
    if(svc.name==='mc') { fs.mkdirSync(path.join(cwd,'common')); fs.copyFileSync(path.join(root,'mc-server-backend/common/minecraft-server-jar-downloads.json'),path.join(cwd,'common/minecraft-server-jar-downloads.json')); }
    const env={...backendEnv,...common,PORT:String(svc.port),FGF_IDP_ISSUER:base,FGF_IDP_CLIENT_ID:`fgf-${svc.name}`,FGF_IDP_CLIENT_SECRET:client.client_secret,FGF_IDP_REDIRECT_URL:svc.url+svc.callback,
      FRONTEND_BASE_URL:svc.url,APP_ENV:'local',JWT_SECRET:crypto.randomBytes(32).toString('hex'),POSTGRES_DSN:'',GLOBAL_MAX_REQUEST_NUM:'1000',
      SERVER_ADDR:`127.0.0.1:${svc.port}`,LIVE_TRADING_MODE:'paper',LIVE_EXECUTION_ENVIRONMENT:'paper',LIVE_KILL_SWITCH:'true',LIVE_TRADING_API_TOKEN:crypto.randomBytes(32).toString('hex'),LIVE_TRADING_CONFIG_DIR:path.join(root,'trading/configs/live'),FGF_IDP_ALLOWED_SUBJECTS:String(profile.id),
    };
    fs.writeFileSync(path.join(cwd,'.env'),Object.entries(env).filter(([k])=>!Object.hasOwn(backendEnv,k)).map(([k,v])=>`${k}=${JSON.stringify(v)}`).join('\n'));
    const child=launch(svc.name,exe(svc.name),svc.name==='trading'?['-env',path.join(cwd,'.env')]:[],cwd,env);
    await ready(`http://127.0.0.1:${svc.port}`+(svc.name==='trading'?'/health':'/Authentication/fgf/login'),child);
  }
  const mc=launch('mc-web',process.execPath,[path.join(root,'mc-server-backend/web/node_modules/vite/bin/vite.js'),'--host','127.0.0.1','--port','15173','--strictPort'],path.join(root,'mc-server-backend/web'),{...process.env,MC_BACKEND_URL:'http://127.0.0.1:18080'});
  const chain=launch('chaintrace-web',process.execPath,[path.join(root,'chaintrace/frontend/node_modules/vinext/dist/cli.js'),'dev','--hostname','127.0.0.1','--port','15175'],path.join(root,'chaintrace/frontend'),{...backendEnv,CHAINTRACE_BACKEND_URL:'http://127.0.0.1:18082',CLOUDFLARE_INCLUDE_PROCESS_ENV:'true'});
  await ready('http://127.0.0.1:15173/login',mc);await ready('http://127.0.0.1:15175/login',chain,120000);
  const info={idp:base,mailbox:'http://127.0.0.1:15526',username:'fgf-local',password,services,run};
  fs.writeFileSync(path.join(run,'access.json'),JSON.stringify(info,null,2));fs.writeFileSync(path.join(output,'current.json'),JSON.stringify(info,null,2));
  console.log('FGF_LOCAL_READY'); for(const svc of services)console.log(`${svc.name}: ${svc.url}`);
  console.log(`Local mailbox: http://127.0.0.1:15526\nLogin credentials: ${path.join(run,'access.json')}`);
  if(process.argv.includes('--test')) { await command(process.execPath,[path.join(root,'web/tests/services.e2e.cjs')],root);cleanup(); }
}
let stopping=false;
function cleanup() { if(stopping)return;stopping=true;for(const child of children)if(child.exitCode===null)child.kill();for(const server of servers)server.close(); }
process.on('SIGINT',()=>{cleanup();process.exit(0)});process.on('SIGTERM',()=>{cleanup();process.exit(0)});
main().catch(err=>{console.error(err.message);cleanup();process.exitCode=1});
