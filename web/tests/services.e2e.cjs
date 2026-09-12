const { chromium } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
const env = JSON.parse(fs.readFileSync(path.join(root,'output/fgf-local/current.json'),'utf8'));
const out = path.join(root,'output/playwright/fgf-services');fs.mkdirSync(out,{recursive:true});
const results=[];
let ssoContext;
async function checkSession(page,svc) {
  if(svc.name==='mc') {
    await page.waitForURL(svc.url+'/',{timeout:15000});
    await page.getByText('WELCOME BACK, OPERATOR',{exact:false}).waitFor();
    const response=await page.evaluate(async()=>{
      const { getAccessToken, getTokenPayload, ensureDeviceId } = await import('/src/utils/authStorage.js');
      const r=await fetch('/user/myservers',{headers:{Authorization:'Bearer '+getAccessToken(),'X-Device-ID':ensureDeviceId(),'C-MPMC-WEB-Header':'mpmc-web-ua-v1'}});
      return { status:r.status, role:getTokenPayload()?.role };
    });
    assert.equal(response.status,200);
    assert.equal(response.role,6);
    await page.locator('.header .username').filter({hasText:'Root User'}).waitFor();
    assert.equal(await page.locator('.welcome-text .highlight').innerText(),'Root User');

  } else {
    const route=svc.name==='trading'?'/api/auth/me':'/api/auth/me';
    const response=await page.request.get(svc.url+route);assert.equal(response.status(),200,await response.text());
    const body=await response.json();assert(svc.name==='trading'?body.user?.sub:body.id);
    if(svc.name==='chaintrace') {
      assert.equal(body.role,6);
      assert.equal(body.display_name,'Root User');
      await page.locator('.user-card .owner-copy strong').filter({hasText:'Root User'}).waitFor();
      assert(!(await page.locator('.user-card .owner-copy').innerText()).includes(body.username));
    } else {
      assert.equal(body.user.name,'Root User');
      await page.getByText('Root User',{exact:true}).waitFor();
    }
    const protectedPath=svc.name==='trading'?'/api/live/session':'/api/investigations';
    assert.equal((await page.request.get(svc.url+protectedPath)).status(),200);
    if(svc.name==='chaintrace') await page.getByText('正在載入調查工作區',{exact:true}).waitFor({state:'hidden'});
  }
}
(async()=>{
 const executablePath=[process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,'C:/Program Files/Google/Chrome/Application/chrome.exe',chromium.executablePath()].filter(Boolean).find(p=>fs.existsSync(p));
 const browser=await chromium.launch({headless:true,executablePath});
 try {
  for(const svc of env.services) {
   const context=await browser.newContext({viewport:{width:1440,height:900}});const page=await context.newPage();const errors=[];
   page.on('pageerror',e=>errors.push(e.message));
   try {
    const before=(await fetch(env.mailbox+'/messages').then(r=>r.json())).length;
    await page.goto(svc.url+'/login');
    await page.getByRole('link',{name:'使用 FGF 登入'}).waitFor();
    fs.writeFileSync(path.join(out,`${svc.name}-login.yml`),await page.locator('body').ariaSnapshot());
    await page.screenshot({path:path.join(out,`${svc.name}-login.png`),fullPage:true});
    await page.getByRole('link',{name:'使用 FGF 登入'}).click();
    await page.waitForURL(env.idp+'/login?**');
    assert(new URL(page.url()).searchParams.get('req_id'));
    await page.getByLabel('帳號 / Email').fill(env.username);
    await page.getByLabel('密碼',{exact:true}).fill('wrong-password');
    await page.getByRole('button',{name:'登入並繼續'}).click();
    await page.getByText('帳號或密碼不正確',{exact:false}).waitFor();
    await page.getByLabel('密碼',{exact:true}).fill(env.password);
    await page.screenshot({path:path.join(out,`${svc.name}-idp.png`),fullPage:true});
    await page.getByRole('button',{name:'登入並繼續'}).click();
    await page.getByRole('heading',{name:'信在路上'}).waitFor();
    let mail=[];for(let i=0;i<40;i++){mail=await fetch(env.mailbox+'/messages').then(r=>r.json());if(mail.length>before)break;await new Promise(r=>setTimeout(r,200));}
    assert(mail.length>before,'SMTP did not receive verification email');
    const link=mail.at(-1).match(/http:\/\/127\.0\.0\.1:15525\/x\/verify\?t=[A-Za-z0-9._~%+-]+/);
    assert(link,'Verification link missing from actual email');
    await page.goto(link[0]);
    await page.waitForURL(svc.url+'/',{timeout:20000});
    await checkSession(page,svc);
    await page.reload();await checkSession(page,svc);
    await page.screenshot({path:path.join(out,`${svc.name}-signed-in.png`),fullPage:true});
    assert.deepEqual(errors,[]);
    if(svc.name==='mc') ssoContext=context;
    else { await page.getByRole('button',{name:'登出',exact:true}).click(); await page.waitForURL(svc.url+'/login'); assert.equal((await page.request.get(svc.url+'/api/auth/me')).status(),401); }
    fs.rmSync(path.join(out,`${svc.name}-failure.png`),{force:true});
    console.log('PASS',svc.name,'logo -> real IDP -> password retry -> SMTP verification -> callback -> authenticated API -> reload');
    results.push({service:svc.name,result:'PASS',flow:'logo, IDP password retry, actual local SMTP, verification, callback, protected API, reload'});
   } catch(err) {await page.screenshot({path:path.join(out,`${svc.name}-failure.png`),fullPage:true});console.error('FAILED URL',page.url());console.error((await page.locator('body').innerText()).slice(0,1200));throw err;}
   finally {if(context!==ssoContext) await context.close();}
  }
  for(const svc of env.services.slice(1)) {
    const page=await ssoContext.newPage();await page.goto(svc.url+'/login');
    await page.getByRole('link',{name:'使用 FGF 登入'}).click();
    await page.waitForURL(svc.url+'/',{timeout:20000});await checkSession(page,svc);
    console.log('PASS',svc.name,'SSO from existing FGF trusted session');await page.close();
  }
  await ssoContext.close();
  // A fresh browser cannot forge the callback or access a protected workspace.
  const context=await browser.newContext();const request=context.request;
  assert.equal((await request.post(env.services[0].url+'/Authentication/fgf/callback',{data:{code:'forged',state:'forged'}})).status(),401);
  assert.equal((await request.get(env.services[1].url+'/api/live/session')).status(),401);
  assert.equal((await request.get(env.services[2].url+'/api/auth/me')).status(),401);
  await context.close();
  console.log('PASS unauthenticated callbacks and protected APIs reject access');
  fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({testedAt:new Date().toISOString(),results},null,2));
 } finally {await browser.close();}
})().catch(err=>{console.error(err);process.exitCode=1});
