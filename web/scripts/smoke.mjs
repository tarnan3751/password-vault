// Headless-browser smoke test of the BUILT bundle against the stub server:
// first-time setup, create/search/reveal entries, lock/unlock, offline unlock
// via the service worker + IndexedDB cache, with CSP enforced; plus keyboard
// operation of dialogs, menus and tabs, touch-target sizes and the phone layout.
// Usage: npm run smoke            against the in-memory stub (scripts/stub-server.ts)
//        npm run smoke -- --real  against a REAL three-node vaultd cluster started in a temp dir
//                                  (scripts/real-cluster.mjs): second user via invite in a second browser
//                                  context, share + verify + accept, then node failures and recovery.
// Needs: npx playwright-core install chromium. SHOTS_DIR=... saves screenshots (light, dark and 390 px).
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { startStub } from './stub-server.ts';

if (process.argv.includes('--real')) {
  const { runReal } = await import('./smoke-real.mjs');
  process.exit(await runReal());
}

const shots = process.env.SHOTS_DIR;
if (shots) mkdirSync(shots, { recursive: true });
const dist = new URL('../dist', import.meta.url).pathname;
const stub = await startStub({ dist });
const steps = [];
const violations = [];
const problems = [];
let browser;
const step = async (name, fn) => {
  try {
    await fn();
    steps.push([name, true]);
    console.log('PASS', name);
  } catch (e) {
    steps.push([name, false]);
    console.log('FAIL', name, '-', String(e.message).split('\n')[0]);
    throw e;
  }
};
const PW = 'correct horse battery staple 42';

try {
  browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 }, permissions: ['clipboard-read', 'clipboard-write'], acceptDownloads: true });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') problems.push(`console.${m.type()}: ${m.text()}`); });
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  // light at 1200 px; with all=true also dark and a 390 px phone (state is restored afterwards)
  const shot = async (n, all = false) => {
    if (!shots) return;
    const snap = (suffix) => page.screenshot({ path: `${shots}/${n}${suffix}.png`, animations: 'disabled' });
    await snap('');
    if (!all) return;
    const vp = page.viewportSize();
    await page.emulateMedia({ colorScheme: 'dark' });
    await snap('-dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await page.setViewportSize({ width: 390, height: 844 });
    await snap('-phone');
    await page.setViewportSize(vp);
  };
  const newEntry = () => page.getByRole('button', { name: 'New entry', exact: true });
  const focused = () => page.evaluate(() => {
    const a = document.activeElement;
    return { tag: a?.tagName, id: a?.id, text: (a?.getAttribute('aria-label') ?? a?.textContent ?? '').trim(), inDialog: !!a?.closest('dialog[open]'), role: a?.getAttribute('role') };
  });
  const dialogOpen = () => page.evaluate(() => !!document.querySelector('dialog[open]'));
  // focus moves after the next render: poll for it
  const expectFocus = async (ok, what) => {
    let f;
    for (let i = 0; i < 40; i++) {
      f = await focused();
      if (ok(f)) return;
      await page.waitForTimeout(50);
    }
    throw new Error(`${what}: ${JSON.stringify(f)}`);
  };

  await step('page loads under the CSP', async () => {
    await page.goto(stub.url + '/');
    await page.getByRole('heading', { name: 'Family Vault' }).waitFor();
    await shot('01-welcome', true);
  });

  await step('first-time setup: rules shown before typing; weak/mismatched passwords block submit with a reason; strong one creates the account', async () => {
    await page.getByRole('button', { name: 'First-time setup' }).click();
    await page.getByText('Your master password needs:').waitFor();
    await page.getByText(/At least 12 characters/).waitFor();
    await page.getByLabel('Username').fill('Alice');
    await page.getByLabel('Bootstrap token').fill(stub.fake.bootstrapToken);
    const submit = page.getByRole('button', { name: 'Create the first account' });
    // the owner's first attempt: 11 characters
    await page.getByLabel('Master password', { exact: true }).fill('elevenchars');
    await page.getByText('(11 so far)').waitFor();
    await page.getByText(/To continue, choose a master password that meets the rules/).waitFor();
    if (!(await submit.isDisabled())) throw new Error('short password should disable submit');
    await page.getByLabel('Master password', { exact: true }).fill('password1');
    await page.getByLabel('Confirm master password').fill('password1');
    await page.getByLabel(/I understand/).check();
    if (!(await submit.isDisabled())) throw new Error('weak password should disable submit');
    await page.getByLabel('Master password', { exact: true }).fill(PW);
    await page.getByLabel('Confirm master password').fill('different');
    if (!(await submit.isDisabled())) throw new Error('mismatch should disable submit');
    // the show-password toggle reveals and hides again
    const toggle = page.getByRole('button', { name: 'Show password' }).nth(1);
    await toggle.click();
    if ((await page.getByLabel('Master password', { exact: true }).getAttribute('type')) !== 'text') throw new Error('show password did not reveal');
    await toggle.click();
    if ((await page.getByLabel('Master password', { exact: true }).getAttribute('type')) !== 'password') throw new Error('show password did not hide');
    await shot('02-setup', true);
    await page.getByLabel('Confirm master password').fill(PW);
    await submit.click();
    await newEntry().waitFor({ timeout: 60_000 });
    await page.getByRole('heading', { name: 'No passwords yet' }).waitFor();
    await page.getByRole('heading', { name: 'Welcome, alice' }).waitFor();
    await shot('03-main-empty', true);
  });

  await step('create a login with a generated password', async () => {
    await newEntry().click();
    await page.getByLabel('Name', { exact: true }).fill('Example Bank');
    await page.getByLabel('Username or email').fill('alice@example.com');
    await page.getByRole('button', { name: 'Generate' }).click();
    await shot('04-generator', true);
    await page.getByRole('button', { name: 'Use this password' }).click();
    const pw = await page.locator('#ed-pw').inputValue();
    if (pw.length !== 20) throw new Error('generated password length ' + pw.length);
    await page.getByLabel('Website 1', { exact: true }).fill('https://bank.example/login');
    // every item field: no spellcheck / autocorrect / autocapitalize
    const bad = await page.evaluate(() => [...document.querySelectorAll('dialog.modal input:not([type=checkbox]):not([type=range]), dialog.modal textarea')]
      .filter((e) => e.getAttribute('spellcheck') !== 'false' || e.getAttribute('autocorrect') !== 'off' || e.getAttribute('autocapitalize') !== 'off').map((e) => e.id || e.getAttribute('aria-label') || e.tagName));
    if (bad.length) throw new Error('fields without spellcheck/autocorrect/autocapitalize off: ' + bad.join(', '));
    await shot('05-editor');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: 'Example Bank' }).first().waitFor();
  });

  await step('detail: password hidden until revealed; copy works', async () => {
    const secret = page.locator('.detail .detail-value').filter({ hasText: '••••' });
    if ((await secret.count()) < 1) throw new Error('password should be masked');
    await page.getByRole('button', { name: 'Reveal Password' }).click();
    await page.getByRole('button', { name: 'Copy Password' }).click();
    await page.getByText(/copied/i).first().waitFor();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    if (clip.length !== 20) throw new Error('clipboard has ' + clip.length);
    await shot('06-detail', true);
  });

  await step('search filters by name/username/url', async () => {
    await newEntry().click();
    await page.getByLabel('Name', { exact: true }).fill('Streaming');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: 'Streaming' }).first().waitFor();
    await page.getByLabel('Search entries').fill('bank.example');
    await page.locator('.entries .entry').first().waitFor();
    if ((await page.locator('.entries .entry').count()) !== 1) throw new Error('search should leave one entry');
    await page.getByLabel('Search entries').fill('no such thing');
    await page.getByRole('heading', { name: 'No matches' }).waitFor();
    await page.getByRole('button', { name: 'Clear the search' }).click();
    if ((await page.locator('.entries .entry').count()) !== 2) throw new Error('clearing the search should show both entries');
  });

  await step('keyboard: dialogs take focus, keep it inside, close on Escape and give it back; unsaved edits are not lost silently', async () => {
    await newEntry().focus();
    await page.keyboard.press('Enter');
    await page.getByRole('dialog', { name: 'New login' }).waitFor();
    await expectFocus((f) => f.inDialog && f.tag === 'INPUT', 'focus should start in the first field');
    let f;
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Tab');
      f = await focused();
      if (!f.inDialog) throw new Error(`Tab #${i + 1} left the dialog: ${JSON.stringify(f)}`);
    }
    for (let i = 0; i < 5; i++) {
      await page.keyboard.press('Shift+Tab');
      if (!(await focused()).inDialog) throw new Error('Shift+Tab left the dialog');
    }
    await page.getByLabel('Name', { exact: true }).fill('Half typed');
    await page.keyboard.press('Escape');
    await page.getByRole('dialog', { name: 'Discard your changes?' }).waitFor();
    await page.keyboard.press('Escape');
    await page.getByRole('dialog', { name: 'Discard your changes?' }).waitFor({ state: 'detached' });
    if ((await page.getByLabel('Name', { exact: true }).inputValue()) !== 'Half typed') throw new Error('Escape on the discard question must keep the draft');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Discard changes' }).click();
    if (await dialogOpen()) throw new Error('editor should be closed');
    await expectFocus((f) => f.text === 'New entry', 'focus should return to New entry');
    // a clean editor closes on Escape straight away
    await page.keyboard.press('Enter');
    await page.getByRole('dialog', { name: 'New login' }).waitFor();
    await page.keyboard.press('Escape');
    if (await dialogOpen()) throw new Error('a clean editor should close on Escape');
    await expectFocus((f) => f.text === 'New entry', 'focus should return to New entry after Escape');
  });

  await step('keyboard: account menu opens with Enter, arrows move, Escape closes and returns focus', async () => {
    const btn = page.getByRole('button', { name: 'alice: account menu' });
    await btn.focus();
    await page.keyboard.press('Enter');
    await page.getByRole('menu').waitFor();
    await expectFocus((f) => f.role === 'menuitem' && /People and fingerprints/.test(f.text), 'first menu item should have focus');
    await page.keyboard.press('ArrowDown');
    await expectFocus((f) => /Account and backup/.test(f.text), 'ArrowDown should move to the next item');
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('ArrowUp');
    await expectFocus((f) => /Sign out/.test(f.text), 'ArrowUp should wrap to the last item');
    await page.keyboard.press('Escape');
    await page.getByRole('menu').waitFor({ state: 'hidden' });
    await expectFocus((f) => f.text === 'alice: account menu', 'Escape should return focus to the menu button');
    await shot('07-menu-closed');
  });

  await step('status: the connection pill explains itself in plain words', async () => {
    await page.locator('.status-btn').click();
    await page.getByText('Everything is working.').waitFor();
    await page.keyboard.press('Escape');
    await page.getByText('Everything is working.').waitFor({ state: 'hidden' });
  });

  await step('vault management: create vault, settings and members tabs (arrow keys) show the fingerprint', async () => {
    await page.getByRole('button', { name: 'New vault', exact: true }).click();
    await page.getByLabel('Vault name').fill('Household');
    await shot('08-new-vault');
    await page.getByRole('button', { name: 'Create vault' }).click();
    await page.getByRole('heading', { name: 'Household is empty' }).waitFor();
    await shot('09-vault-empty', true);
    await page.getByRole('button', { name: 'Vault settings' }).click();
    await page.getByRole('tab', { name: 'General' }).waitFor();
    await shot('10-vault-general', true);
    await page.getByRole('tab', { name: 'General' }).focus();
    await page.keyboard.press('ArrowRight');
    if ((await page.getByRole('tab', { name: /Members/ }).getAttribute('aria-selected')) !== 'true') throw new Error('ArrowRight should select the next tab');
    await page.getByText(/^[0-9a-f]{4}(-[0-9a-f]{4}){7}$/).first().waitFor();
    await page.getByRole('heading', { name: 'Share this vault with someone' }).waitFor();
    await shot('11-vault-members', true);
    await page.keyboard.press('Escape');
  });

  await step('people and fingerprints dialog', async () => {
    await page.getByRole('button', { name: 'alice: account menu' }).click();
    await page.getByRole('menuitem', { name: 'People and fingerprints' }).click();
    await page.getByRole('dialog', { name: 'People and fingerprints' }).waitFor();
    await shot('12-people', true);
    await page.keyboard.press('Escape');
  });

  await step('invite + admin dialog: invite instructions, people, servers summary', async () => {
    await page.getByRole('button', { name: 'alice: account menu' }).click();
    await page.getByRole('menuitem', { name: 'Administration' }).click();
    await page.getByRole('button', { name: 'Create invite' }).click();
    await page.getByRole('heading', { name: 'New invite code' }).waitFor();
    await page.getByText(/choose Join with invite/).first().waitFor();
    // a toast while a dialog is open is announced from inside the dialog (everything outside it is hidden from screen readers)
    await page.locator('.invite').getByRole('button', { name: 'Copy' }).click();
    await page.waitForFunction(() => /Invite code copied/.test(document.querySelector('dialog[open] > .live-p')?.textContent ?? ''));
    await shot('13-admin-invite', true);
    await page.getByRole('tab', { name: 'People' }).click();
    await shot('14-admin-people', true);
    await page.getByRole('tab', { name: 'Servers' }).click();
    await page.getByText(/of 1 server is reachable/).waitFor();
    await shot('15-admin-servers', true);
    await page.keyboard.press('Escape');
  });

  await step('account: fingerprint, password rules, encrypted backup download', async () => {
    await page.getByRole('button', { name: 'alice: account menu' }).click();
    await page.getByRole('menuitem', { name: 'Account and backup' }).click();
    await page.locator('.fp-box .fp.big').first().waitFor();
    await shot('16-account', true);
    await page.getByRole('tab', { name: 'Password' }).click();
    await page.getByText('Your master password needs:').waitFor();
    await shot('17-account-password');
    await page.getByRole('tab', { name: 'Backup' }).click();
    await page.getByLabel('Backup passphrase').fill('a separate long backup passphrase');
    await page.getByLabel('Type it again').fill('a separate long backup passphrase');
    await shot('18-account-backup', true);
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download backup' }).click()]);
    if (!/\.json$/.test(dl.suggestedFilename())) throw new Error('backup file name ' + dl.suggestedFilename());
    await page.getByText(/Backup downloaded/).first().waitFor();
    await page.getByRole('tab', { name: 'Settings' }).click();
    await page.getByLabel('Lock automatically after').waitFor();
    await page.keyboard.press('Escape');
  });

  await step('phone (390 px): header fits in two rows, nothing scrolls sideways, every target is at least 44 px; 640 px (200 % zoom) and 768 px reflow', async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    const h = await page.locator('.topbar').evaluate((e) => e.getBoundingClientRect().height);
    if (h > 120) throw new Error('header too tall: ' + h);
    // checkboxes count with their label (the label is the target)
    const tooSmall = () => page.evaluate(() => [...document.querySelectorAll('button, input:not([type=checkbox]), select, summary, .check, label.inline')]
      .filter((e) => e.getClientRects().length && !e.closest('.sr-only') && !e.closest('.check'))
      .map((e) => [e.getAttribute('aria-label') || e.textContent.trim().slice(0, 30) || e.id || e.tagName, e.getBoundingClientRect()])
      .filter(([, r]) => r.width > 0 && (r.height < 44 || r.width < 24))
      .map(([n, r]) => `${n} ${Math.round(r.width)}x${Math.round(r.height)}`));
    let small = await tooSmall();
    if (small.length) throw new Error('targets under 44 px: ' + small.join('; '));
    // and inside a dialog: the entry editor with the generator and every optional field open
    await newEntry().click();
    await page.getByRole('button', { name: 'Generate' }).click();
    await page.locator('details.more > summary').click();
    await page.getByRole('button', { name: 'Add field' }).click();
    small = await tooSmall();
    if (small.length) throw new Error('targets under 44 px in the editor: ' + small.join('; '));
    await shot('19-phone-editor');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Discard changes' }).click().catch(() => {});
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)) throw new Error('horizontal overflow');
    // 200 % zoom of a 1280 x 800 window is a 640 x 400 viewport; 768 is a tablet: no sideways scrolling either
    for (const [width, height] of [[640, 400], [768, 1024]]) {
      await page.setViewportSize({ width, height });
      if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)) throw new Error(`horizontal overflow at ${width} px`);
    }
    await shot('19-tablet');
    await page.setViewportSize({ width: 1200, height: 800 });
  });

  await step('lock drops keys; unlock with the master password', async () => {
    await page.getByRole('button', { name: 'Lock' }).click();
    await page.getByText(/Locked/).first().waitFor();
    await shot('20-locked', true);
    await page.getByLabel('Master password').fill('wrong password here');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.getByText(/Wrong username or password/).waitFor({ timeout: 60_000 });
    await expectFocus((f) => f.id === 'pw', 'focus should return to the password field after an error');
    await shot('20-unlock-error');
    await page.getByLabel('Master password').fill(PW);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await newEntry().waitFor({ timeout: 60_000 });
  });

  await step('no majority: read-only with the reason next to the disabled controls', async () => {
    stub.fake.node(stub.url).unavailable = true;
    for (let i = 0; i < 30 && !/Read-only/.test(await page.locator('.status').innerText()); i++) {
      await page.evaluate(() => window.dispatchEvent(new Event('online')));
      await page.waitForTimeout(300);
    }
    await page.locator('.banners').getByText('Most of the servers cannot be reached.').waitFor();
    if (!(await newEntry().isDisabled())) throw new Error('writes must be disabled without a majority');
    if (!/Changes are off until a majority of the servers/.test(await page.locator('#new-why').innerText())) throw new Error('the disabled New entry button needs a reason');
    await page.getByText('Example Bank').first().click();
    await page.locator('.detail .note').waitFor();
    await shot('21-read-only', true);
    stub.fake.node(stub.url).unavailable = false;
    for (let i = 0; i < 30 && !/Online/.test(await page.locator('.status').innerText()); i++) {
      await page.evaluate(() => window.dispatchEvent(new Event('online')));
      await page.waitForTimeout(300);
    }
  });

  await step('service worker installed and controlling', async () => {
    await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
    for (let i = 0; i < 40; i++) {
      if (await page.evaluate(() => !!navigator.serviceWorker.controller)) return;
      await page.reload();
      await page.waitForTimeout(250);
      await page.getByLabel('Master password').waitFor().catch(() => {});
      break;
    }
  });

  await step('offline: app shell opens with the server down, unlock from the IndexedDB cache, read-only', async () => {
    // lock first (reload dropped the session already), then take the network away
    await page.goto(stub.url + '/');
    await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
    await stub.close();
    await page.reload();
    await page.getByRole('heading', { name: 'Family Vault' }).waitFor({ timeout: 15_000 });
    await page.getByLabel('Master password').fill(PW);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.getByText('Offline: read-only').first().waitFor({ timeout: 60_000 });
    await page.getByRole('heading', { name: 'Example Bank' }).first().waitFor().catch(async () => {
      await page.getByText('Example Bank').first().waitFor();
    });
    if (!(await newEntry().isDisabled())) throw new Error('writes must be disabled offline');
    await shot('22-offline', true);
  });

  await step('mobile layout works (390px)', async () => {
    await page.setViewportSize({ width: 390, height: 800 });
    await page.getByText('Example Bank').first().click();
    await page.getByRole('button', { name: 'Back', exact: true }).waitFor();
    await expectFocus((f) => f.id === 'detail-title', 'opening an entry on a phone should move focus to it');
    await shot('23-mobile-detail');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    if (overflow) throw new Error('horizontal overflow on mobile');
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await page.getByRole('button', { name: 'Vaults', exact: true }).click();
    await page.getByRole('button', { name: 'Back to entries' }).waitFor();
    await shot('24-mobile-vaults');
    await page.getByRole('button', { name: 'Back to entries' }).click();
  });

  await step('dark mode renders', async () => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.setViewportSize({ width: 1200, height: 800 });
    await shot('25-dark');
  });

  const v = await page.evaluate(() => window.__csp);
  violations.push(...v);
} catch (e) {
  console.log('ABORTED:', e.message);
} finally {
  await browser?.close();
  await stub.close().catch(() => {});
}
const failed = steps.filter(([, ok]) => !ok).length;
console.log(`\nCSP violations: ${violations.length}${violations.length ? ' ' + JSON.stringify(violations) : ''}`);
const real = problems.filter((p) => !/Failed to load resource|net::ERR/.test(p));
console.log(`page errors/console errors (excluding expected offline network failures): ${real.length}${real.length ? '\n  ' + real.join('\n  ') : ''}`);
console.log(`${steps.length - failed}/${steps.length} steps passed`);
process.exit(failed || violations.length || real.length || steps.length < 19 ? 1 : 0);
