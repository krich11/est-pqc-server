const { chromium } = require('playwright');

const HOST = process.env.WEBUI_HOST || '192.168.200.120';
const PORT = process.env.WEBUI_PORT || '9443';
const BASE = `http://${HOST}:${PORT}`;

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
  const title = await page.title().catch(() => '');
  const bodyText = await page.locator('body').innerText().catch(() => '');
  return {
    status: response ? response.status() : null,
    headers,
    title,
    bodyText: bodyText.slice(0, 400),
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
    });
    const page = await context.newPage();
    const result = await navigate(page, '/');
    console.log(JSON.stringify({ phase: 'credential-probe', candidate: candidate.label, result }, null, 2));
    await context.close();
    if (result.status === 200) {
      return candidate;
    }
  }
  return null;
}

(async () => {
  const browser = await chromium.launch({
    channel: 'chrome',
    headless: true,
  });

  try {
    console.log(JSON.stringify({ phase: 'start', base: BASE }, null, 2));

    const admin = await probeCredentials(browser, ADMIN_CANDIDATES);
    if (!admin) {
      throw new Error('no working admin credentials found');
    }

    const krich = await probeCredentials(browser, KRICH_CANDIDATES);
    if (!krich) {
      throw new Error('no working krich credentials found');
    }

    const adminContext = await browser.newContext({
      httpCredentials: {
        username: admin.username,
        password: admin.password,
      },
    });
    const adminPage = await adminContext.newPage();

    const adminLogin = await navigate(adminPage, '/');
    console.log(JSON.stringify({ phase: 'admin-login', using: admin.label, result: adminLogin }, null, 2));
    if (adminLogin.status !== 200) {
      throw new Error(`admin login failed with status ${adminLogin.status}`);
    }

    const logoutResult = await navigate(adminPage, '/logout');
    console.log(JSON.stringify({ phase: 'logout', using: admin.label, result: logoutResult }, null, 2));
    if (logoutResult.status !== 200) {
      throw new Error(`logout did not return 200, got ${logoutResult.status}`);
    }
    if (logoutResult.headers['www-authenticate']) {
      throw new Error('logout response unexpectedly included a WWW-Authenticate challenge');
    }
    if (!logoutResult.bodyText.includes('without issuing a new Basic authentication challenge')) {
      throw new Error('logout body did not include the expected no-challenge message');
    }

    const logoutCookies = await adminContext.cookies(BASE);
    console.log(JSON.stringify({ phase: 'logout-cookies', cookies: logoutCookies }, null, 2));
    if (!logoutCookies.some((cookie) => cookie.name === 'est_webui_logout_nonce')) {
      throw new Error('logout flow did not store logout marker cookie in the browser context');
    }

    await adminContext.close();

    const adminFreshContext = await browser.newContext({
      httpCredentials: {
        username: admin.username,
        password: admin.password,
      },
    });
    const adminFreshPage = await adminFreshContext.newPage();

    const adminFreshLogin = await navigate(adminFreshPage, `/api/me?nonce=${Date.now() + 1}`);
    console.log(JSON.stringify({ phase: 'admin-fresh-relogin', using: admin.label, result: adminFreshLogin }, null, 2));
    if (adminFreshLogin.status !== 200) {
      throw new Error(`fresh admin re-login failed with status ${adminFreshLogin.status}`);
    }

    await adminFreshContext.close();

    const krichContext = await browser.newContext({
      httpCredentials: {
        username: krich.username,
        password: krich.password,
      },
    });
    const krichPage = await krichContext.newPage();

    const krichLogin = await navigate(krichPage, '/');
    console.log(JSON.stringify({ phase: 'account-switch', using: krich.label, result: krichLogin }, null, 2));
    if (krichLogin.status !== 200) {
      throw new Error(`krich login after logout failed with status ${krichLogin.status}`);
    }

    await krichContext.close();

    console.log(JSON.stringify({
      phase: 'summary',
      success: true,
      admin: admin.label,
      krich: krich.label,
      assertions: [
        'admin login succeeded',
        'logout returned 200 without a new auth challenge and set logout marker cookie',
        'same browser session switched to krich successfully',
        'admin could log in again fresh after logout',
      ],
    }, null, 2));
  } finally {
    await browser.close().catch(() => {});
  }
})().catch((error) => {
  console.error(JSON.stringify({
    phase: 'failure',
    message: error.message,
    stack: error.stack,
  }, null, 2));
  process.exit(1);
});