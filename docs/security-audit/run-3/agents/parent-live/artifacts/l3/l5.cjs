// Parent-live check: how does the web approval card render an exec command containing bidi isolate controls?
const { chromium } = require('/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/pw/node_modules/playwright-core');
const fs = require('fs');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const p = await b.newPage();
  await p.goto('http://127.0.0.1:8765/login'); await p.fill('input[name=token]', process.env.HT);
  await Promise.all([p.waitForNavigation(), p.click('button.primary')]);
  await p.goto('http://127.0.0.1:8765/ui/sandboxes/' + fs.readFileSync('sid_bidi', 'utf8').trim()); await p.waitForTimeout(4000);
  const pre = await p.$('#approvals pre');
  await pre.screenshot({ path: 'l5_card.png' });
  console.log('logical text:', JSON.stringify(await pre.innerText()));
  await b.close();
})();
