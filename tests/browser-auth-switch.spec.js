const { test, expect } = require('@playwright/test');

const HOST = process.env.WEBUI_HOST || '192.168.200.120';
const PORT = process.env.WEBUI_PORT || '9443';
const SCHEME = process.env.WEBUI_SCHEME || 'https';
const BASE = `${SCHEME}://${HOST}:${PORT}`;

const ADMIN_CANDIDATES = [
  { username: 'admin', password: 'aruba123', label: 'admin/aruba123' },
];

const KRICH_CANDIDATES = [
  { username: 'krich', password: 'mustang', label: 'krich/mustang' },
];

async function navigate(page, path = '/') {
  const response = await page.goto(`${BASE}${path}`, {
    waitUntil: 'domcontentloaded',
    timeout: 20000,
  });
  const headers = response ? response.headers() : {};
  const bodyText = await page.locator('body').innerText().catch(() => '');
  return {
    status: response ? response.status() : null,
    headers,
    bodyText,
    url: page.url(),
  };
}

async function probeCredentials(browser, candidates) {
  for (const candidate of candidates) {
    const context = await browser.newContext({
      httpCredentials: {
        username: candidate.username,
        password: candidate.password,
      },
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    const result = await navigate(page, '/');
    console.log(
      JSON.stringify(
        { phase: 'credential-probe', candidate: candidate.label, result },
        null,
        2
      )
    );
    await context.close();
    if (result.status === 200) {
      return candidate;
    }
  }
  return null;
}

test('real browser logout blocks stale auth and allows account switching', async ({ browser }) => {
  console.log(JSON.stringify({ phase: 'start', base: BASE }, null, 2));

  const admin = await probeCredentials(browser, ADMIN_CANDIDATES);
  expect(admin, 'expected a working admin credential').toBeTruthy();

  const krich = await probeCredentials(browser, KRICH_CANDIDATES);
  expect(krich, 'expected a working krich credential').toBeTruthy();

  const adminContext = await browser.newContext({
    httpCredentials: {
      username: admin.username,
      password: admin.password,
    },
    ignoreHTTPSErrors: true,
  });
  const adminPage = await adminContext.newPage();

  const adminLogin = await navigate(adminPage, '/');
  console.log(JSON.stringify({ phase: 'admin-login', using: admin.label, result: adminLogin }, null, 2));
  expect(adminLogin.status).toBe(200);

  const logoutResult = await navigate(adminPage, '/logout');
  console.log(JSON.stringify({ phase: 'logout', using: admin.label, result: logoutResult }, null, 2));
  expect(logoutResult.status).toBe(200);
  expect(logoutResult.headers['www-authenticate']).toBeUndefined();
  expect(logoutResult.bodyText).toContain('without issuing a new Basic authentication challenge');

  const logoutCookies = await adminContext.cookies(BASE);
  console.log(JSON.stringify({ phase: 'logout-cookies', cookies: logoutCookies }, null, 2));
  expect(logoutCookies.some((cookie) => cookie.name === 'est_webui_logout_nonce')).toBeTruthy();

  await adminContext.close();

  const adminFreshContext = await browser.newContext({
    httpCredentials: {
      username: admin.username,
      password: admin.password,
    },
    ignoreHTTPSErrors: true,
  });
  const adminFreshPage = await adminFreshContext.newPage();

  const adminFreshRelogin = await navigate(adminFreshPage, `/api/me?nonce=${Date.now() + 1}`);
  console.log(JSON.stringify({ phase: 'admin-fresh-relogin', using: admin.label, result: adminFreshRelogin }, null, 2));
  expect(adminFreshRelogin.status).toBe(200);

  await adminFreshContext.close();

  const krichContext = await browser.newContext({
    httpCredentials: {
      username: krich.username,
      password: krich.password,
    },
    ignoreHTTPSErrors: true,
  });
  const krichPage = await krichContext.newPage();

  const krichLogin = await navigate(krichPage, `/api/me?nonce=${Date.now() + 2}`);
  console.log(JSON.stringify({ phase: 'account-switch', using: krich.label, result: krichLogin }, null, 2));
  expect(krichLogin.status).toBe(200);

  await krichContext.close();
});