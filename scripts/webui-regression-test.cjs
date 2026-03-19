const { chromium } = require("playwright");

const HOST = process.env.WEBUI_HOST || "192.168.200.120";
const PORT = process.env.WEBUI_PORT || "9443";
const SCHEME = process.env.WEBUI_SCHEME || "http";
const BASE = `${SCHEME}://${HOST}:${PORT}`;

const ADMIN_USERNAME = process.env.WEBUI_ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.WEBUI_ADMIN_PASS || "aruba123";

const CERT_CA_PATH = process.env.BROWSER_CERT_CA_PATH || "";
const CERT_LEAF_PATH = process.env.BROWSER_CERT_P12_PATH || "";
const CERT_LEAF_PASSWORD = process.env.BROWSER_CERT_P12_PASSWORD || "";
const CERT_CA_SUBJECT_CN = process.env.BROWSER_CERT_CA_SUBJECT_CN || "";
const CERT_LEAF_SUBJECT_CN = process.env.BROWSER_CERT_LEAF_SUBJECT_CN || "";

const CONFIG_COLLAPSE_STORAGE_PREFIX = "est-webui-config-collapse-";
const tempUsername = `regression-ui-${Date.now()}`;

function log(phase, payload = {}) {
  console.log(
    JSON.stringify(
      {
        phase,
        base: BASE,
        ...payload,
      },
      null,
      2
    )
  );
}

function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function navigate(page, path = "/") {
  const response = await page.goto(`${BASE}${path}`, {
    waitUntil: "domcontentloaded",
    timeout: 30000,
  });
  return response;
}

async function waitForVisibleText(page, selector) {
  await page.waitForFunction(
    ([targetSelector]) => {
      const element = document.querySelector(targetSelector);
      if (!element) {
        return false;
      }
      const text = (element.textContent || "").trim();
      return text !== "" && text !== "Loading…";
    },
    [selector],
    { timeout: 30000 }
  );
}

async function waitForExactText(page, selector, expectedText) {
  await page.waitForFunction(
    ([targetSelector, text]) => {
      const element = document.querySelector(targetSelector);
      if (!element) {
        return false;
      }
      return (element.textContent || "").trim() === text;
    },
    [selector, expectedText],
    { timeout: 30000 }
  );
}

async function waitForInputValue(page, selector) {
  await page.waitForFunction(
    ([targetSelector]) => {
      const element = document.querySelector(targetSelector);
      if (!element) {
        return false;
      }
      return typeof element.value === "string" && element.value.trim() !== "";
    },
    [selector],
    { timeout: 30000 }
  );
}

async function waitForBannerText(page, selector, expectedText) {
  await page.waitForFunction(
    ([targetSelector, text]) => {
      const element = document.querySelector(targetSelector);
      if (!element) {
        return false;
      }
      return (element.textContent || "").includes(text);
    },
    [selector, expectedText],
    { timeout: 30000 }
  );
}

async function clickNav(page, viewName, expectedTitle) {
  await page.locator(`.nav-link[data-view="${viewName}"]`).click();
  await page.waitForFunction(
    ([view]) => {
      const element = document.getElementById(`${view}-view`);
      return element && element.classList.contains("active");
    },
    [viewName],
    { timeout: 15000 }
  );

  const actualTitle = (await page.locator("#page-title").textContent())?.trim();
  assertCondition(
    actualTitle === expectedTitle,
    `expected page title "${expectedTitle}", got "${actualTitle}"`
  );

  log("nav", { viewName, expectedTitle });
}

async function openAndCloseGlobalHelp(page) {
  await page.locator("#open-help-button").click();
  await page.waitForFunction(() => {
    const drawer = document.getElementById("help-drawer");
    return drawer && drawer.classList.contains("open");
  });
  const title = (await page.locator("#help-drawer-title").textContent())?.trim();
  assertCondition(title && title.includes("Dashboard"), "dashboard help drawer did not open");
  await page.locator("#close-help-button").click();
  await page.waitForFunction(() => {
    const drawer = document.getElementById("help-drawer");
    return drawer && !drawer.classList.contains("open");
  });
  log("help-global");
}

async function exerciseConfigurationView(page) {
  await clickNav(page, "configuration", "Configuration");
  await waitForInputValue(page, "#config-listen-port");

  await page.locator("#config-mode-text").click();
  await page.waitForFunction(() => {
    const element = document.getElementById("config-output");
    return element && !element.classList.contains("hidden");
  });
  const textModeOutput = (await page.locator("#config-output").textContent()) || "";
  assertCondition(
    textModeOutput.includes('"listen_port"'),
    "configuration text mode did not show serialized configuration"
  );

  await page.locator("#config-mode-gui").click();
  await page.waitForFunction(() => {
    const element = document.getElementById("config-gui");
    return element && !element.classList.contains("hidden");
  });

  await page.evaluate((prefix) => {
    localStorage.removeItem(`${prefix}server`);
  }, CONFIG_COLLAPSE_STORAGE_PREFIX);

  const serverSection = page.locator('[data-config-section="server"]');
  const serverCollapseTrigger = page.locator('[data-config-collapse="server"]');

  await serverCollapseTrigger.click();
  await page.waitForFunction(() => {
    const section = document.querySelector('[data-config-section="server"]');
    return section && section.classList.contains("collapsed");
  });
  const collapsedState = await page.evaluate((prefix) => {
    return localStorage.getItem(`${prefix}server`);
  }, CONFIG_COLLAPSE_STORAGE_PREFIX);
  assertCondition(
    collapsedState === "true",
    `expected collapsed localStorage state to be "true", got "${collapsedState}"`
  );

  await serverCollapseTrigger.click();
  await page.waitForFunction(() => {
    const section = document.querySelector('[data-config-section="server"]');
    return section && !section.classList.contains("collapsed");
  });

  const expandedState = await page.evaluate((prefix) => {
    return localStorage.getItem(`${prefix}server`);
  }, CONFIG_COLLAPSE_STORAGE_PREFIX);
  assertCondition(
    expandedState === "false",
    `expected expanded localStorage state to be "false", got "${expandedState}"`
  );

  assertCondition(await serverSection.isVisible(), "server configuration section was not visible");
  log("configuration-view");
}

async function exerciseCertificateStoreView(page) {
  await clickNav(page, "certificates", "Certificate Store");
  await waitForVisibleText(page, "#trusted-ca-table-body");
  await waitForVisibleText(page, "#leaf-certificates-table-body");

  assertCondition(
    await page.locator("#upload-trusted-ca-form").isVisible(),
    "trusted CA upload form was not visible"
  );
  assertCondition(
    await page.locator("#upload-leaf-certificate-form").isVisible(),
    "leaf certificate upload form was not visible"
  );

  if (!CERT_CA_PATH || !CERT_LEAF_PATH || !CERT_CA_SUBJECT_CN || !CERT_LEAF_SUBJECT_CN) {
    log("certificate-store-view", { skippedMutationFlow: true });
    return;
  }

  await page.locator("#leaf-certificate-file").setInputFiles(CERT_LEAF_PATH);
  await page.locator("#leaf-certificate-password").fill(CERT_LEAF_PASSWORD);
  await page.locator("#upload-leaf-certificate-button").click();
  await waitForBannerText(
    page,
    "#leaf-certificates-inline-notice",
    "The Trusted CA must be loaded first."
  );

  await page.locator("#trusted-ca-file").setInputFiles(CERT_CA_PATH);
  await page.locator("#upload-trusted-ca-button").click();
  await waitForBannerText(page, "#trusted-ca-inline-notice", "Trusted CA loaded.");

  const trustedCaRow = page.locator("#trusted-ca-table-body tr", {
    hasText: CERT_CA_SUBJECT_CN,
  });
  await trustedCaRow.first().waitFor({ state: "visible", timeout: 30000 });
  await trustedCaRow
    .first()
    .locator('button[data-certificate-action="view-trusted-ca"]')
    .click();

  await page.waitForFunction(() => {
    const drawer = document.getElementById("certificate-detail-drawer");
    return drawer && drawer.classList.contains("open");
  });
  const caDetailText = (await page.locator("#certificate-detail-body").textContent()) || "";
  assertCondition(
    caDetailText.includes(CERT_CA_SUBJECT_CN),
    "trusted CA detail drawer did not contain the expected subject CN"
  );
  await page.locator("#close-certificate-detail-button").click();

  await page.locator("#leaf-certificate-file").setInputFiles(CERT_LEAF_PATH);
  await page.locator("#leaf-certificate-password").fill(CERT_LEAF_PASSWORD);
  await page.locator("#upload-leaf-certificate-button").click();
  await waitForBannerText(page, "#leaf-certificates-inline-notice", "Leaf certificate loaded.");

  const leafRow = page.locator("#leaf-certificates-table-body tr", {
    hasText: CERT_LEAF_SUBJECT_CN,
  });
  await leafRow.first().waitFor({ state: "visible", timeout: 30000 });
  await leafRow.first().locator('button[data-certificate-action="view-leaf"]').click();

  await page.waitForFunction(() => {
    const drawer = document.getElementById("certificate-detail-drawer");
    return drawer && drawer.classList.contains("open");
  });
  const leafDetailText = (await page.locator("#certificate-detail-body").textContent()) || "";
  assertCondition(
    leafDetailText.includes(CERT_LEAF_SUBJECT_CN),
    "leaf certificate detail drawer did not contain the expected subject CN"
  );
  await page.locator("#close-certificate-detail-button").click();

  await leafRow.first().locator('button[data-certificate-action="delete-leaf"]').click();
  await page.waitForFunction(
    (subjectCn) => {
      const table = document.getElementById("leaf-certificates-table-body");
      return table && !(table.textContent || "").includes(subjectCn);
    },
    CERT_LEAF_SUBJECT_CN,
    { timeout: 30000 }
  );

  await trustedCaRow.first().locator('button[data-certificate-action="delete-trusted-ca"]').click();
  await page.waitForFunction(
    (subjectCn) => {
      const table = document.getElementById("trusted-ca-table-body");
      return table && !(table.textContent || "").includes(subjectCn);
    },
    CERT_CA_SUBJECT_CN,
    { timeout: 30000 }
  );

  log("certificate-store-view", {
    uploadedTrustedCa: CERT_CA_SUBJECT_CN,
    uploadedLeaf: CERT_LEAF_SUBJECT_CN,
  });
}

async function exerciseAuthorizationView(page) {
  await clickNav(page, "authorization", "Authorization Rules");
  await page.locator("#rules-default-action").waitFor({ state: "visible", timeout: 30000 });
  assertCondition(
    await page.locator("#save-rules-button").isVisible(),
    "save rules button was not visible"
  );
  assertCondition(
    await page.locator("#add-rule-button").isVisible(),
    "add rule button was not visible"
  );
  log("authorization-view");
}

async function exercisePendingAndHistoryViews(page) {
  await clickNav(page, "queue", "Pending Enrollments");
  await page.locator("#pending-enrollments-container").waitFor({ state: "visible", timeout: 30000 });

  await clickNav(page, "history", "Enrollment History");
  await page
    .locator("#enrollment-history-container")
    .waitFor({ state: "visible", timeout: 30000 });

  log("pending-history-views");
}

async function exerciseUsersView(page) {
  await clickNav(page, "users", "Users");
  await waitForVisibleText(page, "#account-username");
  await page.locator("#create-username").fill(tempUsername);
  await page.locator("#create-password").fill("TempPass!123");
  await page.locator("#create-role").selectOption("admin");
  await page.locator('#create-user-form button[type="submit"]').click();
  await waitForBannerText(page, "#message-banner", `User ${tempUsername} created.`);

  const userRow = page.locator("#users-table-body tr", { hasText: tempUsername });
  await userRow.first().waitFor({ state: "visible", timeout: 30000 });

  await userRow.first().locator('button[data-action="delete-user"]').click();
  await waitForBannerText(page, "#message-banner", `User ${tempUsername} deleted.`);
  await page.waitForFunction(
    (username) => {
      const table = document.getElementById("users-table-body");
      return table && !(table.textContent || "").includes(username);
    },
    tempUsername,
    { timeout: 30000 }
  );

  log("users-view", { tempUsername });
}

async function exerciseSystemdView(page) {
  await clickNav(page, "systemd", "systemd");
  await waitForVisibleText(page, "#systemd-detail-unit");
  await page.locator("#reload-systemd-button").click();
  await waitForVisibleText(page, "#systemd-detail-active-state");
  log("systemd-view");
}

(async () => {
  const browser = await chromium.launch({
    channel: "chrome",
    headless: true,
  });

  const context = await browser.newContext({
    httpCredentials: {
      username: ADMIN_USERNAME,
      password: ADMIN_PASSWORD,
    },
  });

  context.on("dialog", async (dialog) => {
    const message = dialog.message();
    log("dialog", { type: dialog.type(), message });

    if (
      message.includes("Delete user") ||
      message.includes("Delete this Trusted CA certificate?") ||
      message.includes("Delete this leaf certificate?")
    ) {
      await dialog.accept();
      return;
    }

    await dialog.dismiss();
  });

  const page = await context.newPage();

  try {
    const response = await navigate(page, "/");
    const status = response ? response.status() : null;
    assertCondition(status === 200, `expected initial page load status 200, got ${status}`);

    await waitForExactText(page, "#current-username", ADMIN_USERNAME);
    const currentUsername = (await page.locator("#current-username").textContent())?.trim();
    assertCondition(
      currentUsername === ADMIN_USERNAME,
      `expected authenticated username "${ADMIN_USERNAME}", got "${currentUsername}"`
    );

    log("start", { authenticatedAs: currentUsername });

    await openAndCloseGlobalHelp(page);
    await clickNav(page, "dashboard", "Dashboard");
    await exerciseConfigurationView(page);
    await exerciseCertificateStoreView(page);
    await exerciseAuthorizationView(page);
    await exercisePendingAndHistoryViews(page);
    await exerciseUsersView(page);
    await exerciseSystemdView(page);

    log("summary", {
      success: true,
      assertions: [
        "authenticated admin session loaded successfully",
        "global help drawer opened and closed",
        "all sidebar views navigated successfully",
        "configuration GUI/text mode and collapse state behaved correctly",
        "certificate store GUI flow completed",
        "authorization, pending, and history views rendered",
        "temporary user create/delete flow worked",
        "systemd view reloaded successfully",
      ],
    });
  } finally {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
})().catch((error) => {
  console.error(
    JSON.stringify(
      {
        phase: "failure",
        message: error.message,
        stack: error.stack,
        base: BASE,
      },
      null,
      2
    )
  );
  process.exit(1);
});