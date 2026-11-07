// Real-cluster browser smoke test (see smoke.mjs). Always kills the vaultd
// processes and removes the temp dir, even on failure.
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { startCluster } from './real-cluster.mjs';

const FP = /^[0-9a-f]{4}(-[0-9a-f]{4}){7}$/;
const PW_A = 'real cluster passphrase number one';
const PW_B = 'second cluster passphrase for him';

export async function runReal() {
  const shots = process.env.SHOTS_DIR;
  if (shots) mkdirSync(shots, { recursive: true });
  const steps = [];
  const violations = [];
  const problems = [];
  let cluster;
  let browser;
  const dbg = [];
  const allConsole = [];
  const step = async (name, fn) => {
    try {
      await fn();
      steps.push([name, true]);
      console.log('PASS', name);
    } catch (e) {
      steps.push([name, false]);
      console.log('FAIL', name, '-', String(e.message).split('\n')[0]);
      for (const u of dbg) console.log(`   [${u.label}] toasts/status:`, JSON.stringify(await u.page.locator('.toasts, .status, .banners').allInnerTexts().catch(() => [])), (await u.page.evaluate(() => window.__csp).catch(() => [])).join(';'));
      if (process.env.DEBUG_CONSOLE) console.log(allConsole.join('\n'));
      throw e;
    }
  };
  try {
    cluster = await startCluster();
    console.log('cluster:', cluster.urls.join(' '));
    browser = await chromium.launch();
    const mk = async (label) => {
      const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
      const page = await ctx.newPage();
      dbg.push({ page, label });
      page.on('console', (m) => allConsole.push(`${label} ${m.type()}: ${m.text()}`));
      page.on('pageerror', (e) => problems.push(`${label} pageerror: ${e.message}`));
      page.on('console', (m) => { if (m.type() === 'error') problems.push(`${label} console: ${m.text()}`); });
      await page.addInitScript(() => {
        window.__csp = [];
        document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
      });
      return { ctx, page, label };
    };
    const A = await mk('alice');
    const B = await mk('bob');
    const shot = async (u, n) => { if (shots) await u.page.screenshot({ path: `${shots}/real-${n}.png`, animations: 'disabled' }); };
    // The app polls every 30 s; the same code path is triggered by the browser's "online" event.
    const poke = (u) => u.page.evaluate(() => window.dispatchEvent(new Event('online')));
    const statusText = (u) => u.page.locator('.status').first().innerText();
    const waitStatus = async (u, re, ms = 45000) => {
      const t0 = Date.now();
      let last = '';
      while (Date.now() - t0 < ms) {
        await poke(u);
        last = await statusText(u).catch(() => '');
        if (re.test(last)) return last;
        await u.page.waitForTimeout(1000);
      }
      throw new Error(`status never matched ${re}; last: ${last}`);
    };
    const aliceOrigin = cluster.urls[0];

    await step('alice: first-time setup on node 1 (real Argon2id in WASM under the real CSP)', async () => {
      await A.page.goto(aliceOrigin + '/');
      await A.page.getByRole('button', { name: 'First-time setup' }).click();
      await A.page.getByLabel('Username').fill('alice');
      await A.page.getByLabel('Bootstrap token').fill(cluster.token);
      await A.page.getByLabel('Master password', { exact: true }).fill(PW_A);
      await A.page.getByLabel('Confirm master password').fill(PW_A);
      await A.page.getByLabel(/I understand/).check();
      await A.page.getByRole('button', { name: 'Create the first account' }).click();
      await A.page.getByRole('button', { name: 'New entry', exact: true }).waitFor({ timeout: 90000 });
      await shot(A, '01-alice-main');
    });

    await step('alice: create a shared vault and an entry', async () => {
      await A.page.getByRole('button', { name: 'New vault', exact: true }).click();
      await A.page.getByLabel('Vault name').fill('Household');
      await A.page.getByRole('button', { name: 'Create vault' }).click();
      await A.page.getByRole('button', { name: 'Share', exact: true }).waitFor();
      await A.page.getByRole('button', { name: 'New entry', exact: true }).click();
      await A.page.getByLabel('Name', { exact: true }).fill('Router admin');
      await A.page.getByLabel('Username or email').fill('admin');
      await A.page.locator('#ed-pw').fill('router-secret-1');
      await A.page.getByRole('button', { name: 'Save' }).click();
      await A.page.getByRole('heading', { name: 'Router admin' }).first().waitFor();
    });

    let invite = '';
    let aliceFp = '';
    await step('alice: create an invite; note her own fingerprint', async () => {
      await A.page.getByRole('button', { name: 'alice: account menu' }).click();
      await A.page.getByRole('menuitem', { name: 'Administration' }).click();
      await A.page.getByRole('button', { name: 'Create invite' }).click();
      invite = await A.page.locator('.invite-code').first().innerText();
      if (!/^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/.test(invite)) throw new Error('invite format: ' + invite);
      await A.page.keyboard.press('Escape');
      await A.page.getByRole('button', { name: 'alice: account menu' }).click();
      await A.page.getByRole('menuitem', { name: 'Account and backup' }).click();
      aliceFp = await A.page.locator('.fp-box .fp.big').first().innerText();
      if (!FP.test(aliceFp)) throw new Error('fingerprint format: ' + aliceFp);
      await A.page.keyboard.press('Escape');
    });

    let bobFp = '';
    await step('bob (second browser context, loaded from node 2): join with the invite', async () => {
      await B.page.goto(cluster.urls[1] + '/');
      await B.page.getByRole('button', { name: 'Join with invite' }).click();
      await B.page.getByLabel('Username').fill('bob');
      await B.page.getByLabel('Invite code').fill(invite);
      await B.page.getByLabel('Master password', { exact: true }).fill(PW_B);
      await B.page.getByLabel('Confirm master password').fill(PW_B);
      await B.page.getByLabel(/I understand/).check();
      await B.page.getByRole('button', { name: 'Create account' }).click();
      await B.page.getByRole('button', { name: 'New entry', exact: true }).waitFor({ timeout: 90000 });
      await B.page.getByRole('button', { name: 'bob: account menu' }).click();
      await B.page.getByRole('menuitem', { name: 'Account and backup' }).click();
      bobFp = await B.page.locator('.fp-box .fp.big').first().innerText();
      await B.page.keyboard.press('Escape');
      if (!FP.test(bobFp)) throw new Error('bob fingerprint: ' + bobFp);
    });

    await step('alice: share with bob after comparing his fingerprint', async () => {
      await poke(A); // pick up bob's registration
      await A.page.waitForTimeout(1500);
      await A.page.getByRole('button', { name: 'Share', exact: true }).click();
      await A.page.getByRole('tab', { name: /Members/ }).click();
      await A.page.getByRole('textbox', { name: 'Username' }).fill('bob');
      await A.page.getByRole('button', { name: 'Look up' }).click();
      const shown = await A.page.locator('.fp-box .fp.big').first().innerText();
      if (shown !== bobFp) throw new Error(`fingerprint shown to alice ${shown} != bob's own ${bobFp}`);
      await shot(A, '02-alice-share');
      await A.page.getByLabel(/matches what bob sees/).check();
      await A.page.getByRole('button', { name: 'Share with bob' }).click();
      await A.page.getByText(/Shared with bob/).first().waitFor();
      await A.page.keyboard.press('Escape');
    });

    await step('bob: the share is pending (closed) until he compares alice\'s fingerprint, then it opens', async () => {
      await poke(B);
      await B.page.locator('.vault-link.pending').first().waitFor({ timeout: 20000 });
      await B.page.locator('.vault-link.pending').first().click();
      const shown = await B.page.locator('.fp-box .fp.big').first().innerText();
      if (shown !== aliceFp) throw new Error(`fingerprint shown to bob ${shown} != alice's ${aliceFp}`);
      await shot(B, '03-bob-pending');
      const accept = B.page.getByRole('button', { name: /Verify alice and open the vault/ });
      if (!(await accept.isDisabled())) throw new Error('accept must stay disabled until the comparison is confirmed');
      await B.page.getByLabel(/I compared it and it matches/).check();
      await accept.click();
      await B.page.getByText('Router admin').first().waitFor({ timeout: 20000 });
      await shot(B, '04-bob-open');
    });

    await step('kill the node alice\'s page was loaded from: the open page fails over (real CORS + CSP connect-src)', async () => {
      await cluster.kill(0);
      await A.page.getByRole('button', { name: 'New entry', exact: true }).click();
      await A.page.getByLabel('Name', { exact: true }).fill('After failover');
      await A.page.getByRole('button', { name: 'Save' }).click();
      await A.page.getByRole('heading', { name: 'After failover' }).first().waitFor({ timeout: 40000 });
      const st = await statusText(A);
      if (st.includes(new URL(aliceOrigin).host)) throw new Error('still reports the killed node: ' + st);
      if (!/Online/.test(st)) throw new Error('not online: ' + st);
      await shot(A, '05-alice-failover');
    });

    await step('kill a second node: no quorum -> read-only with a clear status, writes disabled', async () => {
      await cluster.kill(1);
      const st = await waitStatus(A, /Read-only|Offline/);
      console.log('   status:', st.replace(/\s+/g, ' '));
      if (!(await A.page.getByRole('button', { name: 'New entry', exact: true }).isDisabled())) throw new Error('writes must be disabled');
      await A.page.locator('.banners').getByText(/Most of the servers cannot be reached|You are offline/).first().waitFor();
      await shot(A, '06-alice-readonly');
    });

    await step('restart the nodes: the page recovers to Online and writes work again', async () => {
      await cluster.restart(0);
      await cluster.restart(1);
      await cluster.waitForLeader();
      await waitStatus(A, /Online/, 60000);
      await A.page.getByRole('button', { name: 'New entry', exact: true }).click();
      await A.page.getByLabel('Name', { exact: true }).fill('After recovery');
      await A.page.getByRole('button', { name: 'Save' }).click();
      await A.page.getByRole('heading', { name: 'After recovery' }).first().waitFor({ timeout: 40000 });
      await shot(A, '07-alice-recovered');
    });

    await step('service worker (real server headers/scope): controlling the page; with ALL nodes down the shell loads from its cache and an offline unlock works read-only', async () => {
      // make sure the worker is installed, activated and controlling this page
      await A.page.goto(aliceOrigin + '/');
      await A.page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
      for (let i = 0; i < 20 && !(await A.page.evaluate(() => !!navigator.serviceWorker.controller)); i++) {
        await A.page.reload();
        await A.page.waitForTimeout(300);
      }
      const sw = await A.page.evaluate(async () => {
        const reg = await navigator.serviceWorker.getRegistration('/');
        const keys = await caches.keys();
        const cache = keys.length ? await (await caches.open(keys[0])).keys() : [];
        return { controlling: !!navigator.serviceWorker.controller, scope: reg?.scope, active: reg?.active?.state, cached: cache.map((r) => new URL(r.url).pathname).sort() };
      });
      if (!sw.controlling || sw.active !== 'activated') throw new Error('worker not controlling: ' + JSON.stringify(sw));
      if (!sw.cached.includes('/') || !sw.cached.some((p) => p.startsWith('/assets/') && p.endsWith('.js'))) throw new Error('shell not cached: ' + JSON.stringify(sw));
      console.log('   worker scope', sw.scope, 'cached', sw.cached.join(' '));
      // everything down
      await cluster.killAll();
      await A.page.reload();
      await A.page.getByRole('heading', { name: 'Family Vault' }).waitFor({ timeout: 20000 });
      await A.page.getByLabel('Master password').fill(PW_A);
      await A.page.getByRole('button', { name: 'Unlock' }).click();
      await A.page.getByText('Offline: read-only').first().waitFor({ timeout: 90000 });
      await A.page.getByText('Router admin').first().waitFor();
      if (!(await A.page.getByRole('button', { name: 'New entry', exact: true }).isDisabled())) throw new Error('writes must be disabled offline');
      await shot(A, '08-alice-all-down');
      // and back
      await cluster.startAll();
      await waitStatus(A, /Online/, 90000);
      await A.page.getByRole('button', { name: 'New entry', exact: true }).click();
      await A.page.getByLabel('Name', { exact: true }).fill('After total outage');
      await A.page.getByRole('button', { name: 'Save' }).click();
      await A.page.getByRole('heading', { name: 'After total outage' }).first().waitFor({ timeout: 40000 });
    });

    for (const u of [A, B]) violations.push(...(await u.page.evaluate(() => window.__csp)));
  } catch (e) {
    console.log('ABORTED:', e.message);
  } finally {
    await browser?.close().catch(() => {});
    await cluster?.stop().catch(() => {});
  }
  const failed = steps.filter(([, ok]) => !ok).length;
  console.log(`\nCSP violations: ${violations.length}${violations.length ? ' ' + JSON.stringify(violations) : ''}`);
  // network failures while nodes are killed are expected; anything else is not
  const real = problems.filter((p) => !/Failed to load resource|net::ERR|ERR_CONNECTION|Failed to fetch|CORS|NetworkError/i.test(p));
  console.log(`unexpected page/console errors: ${real.length}${real.length ? '\n  ' + real.join('\n  ') : ''}`);
  console.log(`${steps.length - failed}/${steps.length} steps passed`);
  return failed || violations.length || real.length || steps.length < 10 ? 1 : 0;
}
