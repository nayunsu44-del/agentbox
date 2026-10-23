// Parent-live check: does a plaintext http page on the same host get the Secure SameSite=Strict cookie attached to a POST to the https UI?
const { chromium } = require('/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/pw/node_modules/playwright-core');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const ctx = await b.newContext({ ignoreHTTPSErrors: true });
  const p = await ctx.newPage();
  await p.goto('https://127.0.0.1/login');
  await p.fill('input[name=token]', process.env.HT2);
  await Promise.all([p.waitForNavigation(), p.click('button.primary')]);
  console.log('logged in at', p.url(), 'cookies', (await ctx.cookies()).map(c => c.name + ' secure=' + c.secure + ' samesite=' + c.sameSite));
  const reqs = [];
  ctx.on('request', r => { if (r.url().includes('/logout')) reqs.push(r); });
  const q = await ctx.newPage();
  await q.goto('http://127.0.0.1/csrf.html'); await q.waitForTimeout(3000);
  for (const r of reqs) console.log('POST /logout sent cookie header:', /agentbox_session=/.test((await r.allHeaders())['cookie'] || ''), 'origin:', (await r.allHeaders())['origin']);
  const r2 = await p.goto('https://127.0.0.1/ui');
  console.log('original tab still logged in after attack page:', !p.url().includes('/login'));
  await b.close();
})();
