const views = {
  dashboard: {
    title: "Dashboard",
    subtitle: "Server health, enrollment state, and administrative actions.",
  },
  configuration: {
    title: "Configuration",
    subtitle: "Edit runtime configuration or inspect the serialized configuration.",
  },
  certificates: {
    title: "Certificate Store",
    subtitle: "Manage Trusted CA certificates and P12 leaf certificates for EST and WebUI use.",
  },
  authorization: {
    title: "Authorization Rules",
    subtitle: "Define ordered policy rules and the default behavior for enrollment requests.",
  },
  queue: {
    title: "Pending Enrollments",
    subtitle: "Deferred EST requests awaiting administrator approval or rejection.",
  },
  history: {
    title: "Enrollment History",
    subtitle: "Issued enrollment artifacts and persisted request history.",
  },
  users: {
    title: "Users",
    subtitle: "Manage WebUI accounts and change your own password.",
  },
  systemd: {
    title: "systemd",
    subtitle: "Inspect service state, recent journal output, and lifecycle actions.",
  },
};

const CONFIG_MODE_STORAGE_KEY = "est-webui-config-mode";
const CONFIG_COLLAPSE_STORAGE_PREFIX = "est-webui-config-collapse-";

const state = {
  activeView: "dashboard",
  currentUser: null,
  users: [],
  config: null,
  rules: null,
  pendingEnrollments: [],
  enrollmentHistory: [],
  systemd: null,
  trustedCa: [],
  leafCertificates: [],
  configMode: localStorage.getItem(CONFIG_MODE_STORAGE_KEY) || "gui",
  helpOpen: false,
  certificateDetailOpen: false,
};

const pageTitle = document.getElementById("page-title");
const pageSubtitle = document.getElementById("page-subtitle");
const messageBanner = document.getElementById("message-banner");
const configOutput = document.getElementById("config-output");
const configGui = document.getElementById("config-gui");
const saveConfigButton = document.getElementById("save-config-button");
const readOnlyBadge = document.getElementById("read-only-badge");
const usersTableBody = document.getElementById("users-table-body");
const userManagementPanel = document.getElementById("user-management-panel");
const createUserForm = document.getElementById("create-user-form");
const changePasswordForm = document.getElementById("change-password-form");
const reloadUsersButton = document.getElementById("reload-users-button");
const logoutButton = document.getElementById("logout-button");
const authorizationRulesContainer = document.getElementById("authorization-rules-container");
const saveRulesButton = document.getElementById("save-rules-button");
const addRuleButton = document.getElementById("add-rule-button");
const rulesDefaultAction = document.getElementById("rules-default-action");
const pendingEnrollmentsContainer = document.getElementById("pending-enrollments-container");
const enrollmentHistoryContainer = document.getElementById("enrollment-history-container");
const reloadPendingButton = document.getElementById("reload-pending-button");
const reloadHistoryButton = document.getElementById("reload-history-button");
const reloadSystemdButton = document.getElementById("reload-systemd-button");
const systemdActionResult = document.getElementById("systemd-action-result");
const helpDrawer = document.getElementById("help-drawer");
const helpDrawerTitle = document.getElementById("help-drawer-title");
const helpDrawerSubtitle = document.getElementById("help-drawer-subtitle");
const helpDrawerBody = document.getElementById("help-drawer-body");
const helpBackdrop = document.getElementById("help-backdrop");
const openHelpButton = document.getElementById("open-help-button");
const closeHelpButton = document.getElementById("close-help-button");
const configModeButtons = document.querySelectorAll("[data-config-mode]");
const systemdActionButtons = document.querySelectorAll("[data-systemd-action]");
const configInputs = document.querySelectorAll("[data-config-path]");
const configCollapseButtons = document.querySelectorAll("[data-config-collapse]");
const trustedCaTableBody = document.getElementById("trusted-ca-table-body");
const leafCertificatesTableBody = document.getElementById("leaf-certificates-table-body");
const uploadTrustedCaForm = document.getElementById("upload-trusted-ca-form");
const uploadLeafCertificateForm = document.getElementById("upload-leaf-certificate-form");
const reloadTrustedCaButton = document.getElementById("reload-trusted-ca-button");
const reloadLeafCertificatesButton = document.getElementById("reload-leaf-certificates-button");
const trustedCaInlineNotice = document.getElementById("trusted-ca-inline-notice");
const leafCertificatesInlineNotice = document.getElementById("leaf-certificates-inline-notice");
const certificateDetailDrawer = document.getElementById("certificate-detail-drawer");
const certificateDetailBackdrop = document.getElementById("certificate-detail-backdrop");
const certificateDetailTitle = document.getElementById("certificate-detail-title");
const certificateDetailSubtitle = document.getElementById("certificate-detail-subtitle");
const certificateDetailBody = document.getElementById("certificate-detail-body");
const closeCertificateDetailButton = document.getElementById("close-certificate-detail-button");

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});

document.getElementById("refresh-button")?.addEventListener("click", () => void refreshAll());
logoutButton?.addEventListener("click", handleLogout);
reloadUsersButton?.addEventListener("click", () => void refreshUsers());
reloadPendingButton?.addEventListener("click", () => void refreshPendingEnrollments());
reloadHistoryButton?.addEventListener("click", () => void refreshEnrollmentHistory());
reloadSystemdButton?.addEventListener("click", () => void refreshSystemdStatus());
reloadTrustedCaButton?.addEventListener("click", () => void refreshTrustedCa());
reloadLeafCertificatesButton?.addEventListener("click", () => void refreshLeafCertificates());
createUserForm?.addEventListener("submit", (event) => void handleCreateUser(event));
changePasswordForm?.addEventListener("submit", (event) => void handleChangeOwnPassword(event));
saveRulesButton?.addEventListener("click", () => void handleSaveRules());
saveConfigButton?.addEventListener("click", () => void handleSaveConfig());
addRuleButton?.addEventListener("click", handleAddRule);
uploadTrustedCaForm?.addEventListener("submit", (event) => void handleUploadTrustedCa(event));
uploadLeafCertificateForm?.addEventListener("submit", (event) => void handleUploadLeafCertificate(event));
openHelpButton?.addEventListener("click", () => openHelp(state.activeView));
closeHelpButton?.addEventListener("click", closeHelp);
helpBackdrop?.addEventListener("click", closeHelp);
closeCertificateDetailButton?.addEventListener("click", closeCertificateDetail);
certificateDetailBackdrop?.addEventListener("click", closeCertificateDetail);

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && state.helpOpen) {
    closeHelp();
  }
  if (event.key === "Escape" && state.certificateDetailOpen) {
    closeCertificateDetail();
  }
});

document.querySelectorAll("[data-help-view]").forEach((button) => {
  button.addEventListener("click", () => openHelp(button.dataset.helpView || state.activeView));
});

configModeButtons.forEach((button) => {
  button.addEventListener("click", () => setConfigMode(button.dataset.configMode));
});

configCollapseButtons.forEach((button) => {
  button.addEventListener("click", () => toggleConfigSection(button.dataset.configCollapse));
});

systemdActionButtons.forEach((button) => {
  button.addEventListener("click", () => void handleSystemdAction(button.dataset.systemdAction));
});

function setActiveView(viewName) {
  state.activeView = viewName;

  document.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === viewName);
  });

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `${viewName}-view`);
  });

  const meta = views[viewName];
  if (meta) {
    pageTitle.textContent = meta.title;
    pageSubtitle.textContent = meta.subtitle;
  }

  const pageHelpButton = document.querySelector(".page-heading-row [data-help-view]");
  if (pageHelpButton) {
    pageHelpButton.dataset.helpView = viewName;
  }

  if (state.helpOpen) {
    renderHelp(viewName);
  }
}

function showMessage(text, isError = false) {
  messageBanner.textContent = text;
  messageBanner.classList.remove("hidden", "error");
  if (isError) {
    messageBanner.classList.add("error");
  }
}

function clearMessage() {
  messageBanner.textContent = "";
  messageBanner.classList.add("hidden");
  messageBanner.classList.remove("error");
}

function showInlineNotice(element, text, isError = false) {
  if (!element) {
    return;
  }
  element.textContent = text;
  element.classList.remove("hidden", "error");
  if (isError) {
    element.classList.add("error");
  } else {
    element.classList.remove("error");
  }
}

function clearInlineNotice(element) {
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
  element.classList.remove("error");
}

function handleLogout() {
  window.location.assign("/logout");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

function setHidden(element, hidden) {
  if (!element) {
    return;
  }
  element.classList.toggle("hidden", hidden);
}

function canManageUsers() {
  return Boolean(state.currentUser?.can_manage_users);
}

function canEditConfig() {
  return Boolean(state.currentUser?.can_edit_config);
}

function canModifyPolicy() {
  return Boolean(state.currentUser?.can_modify_policy);
}

function canManageCertificates() {
  return Boolean(state.currentUser?.can_manage_certificates);
}

function canManageEnrollments() {
  return Boolean(state.currentUser?.can_manage_enrollments);
}

function canManageSystemd() {
  return Boolean(state.currentUser?.can_manage_systemd);
}

function isReadOnlyUser() {
  return Boolean(state.currentUser?.read_only);
}

function applyPermissionState() {
  setHidden(readOnlyBadge, !isReadOnlyUser());
  setHidden(saveConfigButton, !canEditConfig());
  setHidden(saveRulesButton, !canModifyPolicy());
  setHidden(addRuleButton, !canModifyPolicy());
  setHidden(createUserForm, !canManageUsers());

  configInputs.forEach((input) => {
    if (input.readOnly) {
      return;
    }
    input.disabled = !canEditConfig();
  });

  if (rulesDefaultAction) {
    rulesDefaultAction.disabled = !canModifyPolicy();
  }

  systemdActionButtons.forEach((button) => {
    button.disabled = !canManageSystemd();
  });

  if (uploadTrustedCaForm) {
    uploadTrustedCaForm
      .querySelectorAll("input, button")
      .forEach((element) => {
        element.disabled = !canManageCertificates();
      });
  }

  if (uploadLeafCertificateForm) {
    uploadLeafCertificateForm
      .querySelectorAll("input, button")
      .forEach((element) => {
        element.disabled = !canManageCertificates();
      });
  }
}

function setIdentity(user) {
  state.currentUser = user;

  const roleText = user?.role ?? "unknown";
  const usernameText = user?.username ?? "Unknown user";

  setText("current-username", usernameText);
  setText("current-role", roleText);
  setText("dashboard-current-user", `${usernameText} (${roleText})`);

  setText("account-username", usernameText);
  setText("account-role", roleText);
  setText("account-can-manage-users", user?.can_manage_users ? "yes" : "no");

  setHidden(userManagementPanel, false);
  applyPermissionState();
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value ?? "—";
  }
}

function formatBoolean(value) {
  return value ? "yes" : "no";
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (typeof value === "boolean") {
    return formatBoolean(value);
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return String(value);
}

function formatBytes(rawValue) {
  const value = Number(rawValue);
  if (!Number.isFinite(value) || value <= 0) {
    return formatValue(rawValue);
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let remainder = value;
  let index = 0;

  while (remainder >= 1024 && index < units.length - 1) {
    remainder /= 1024;
    index += 1;
  }

  return `${remainder.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function getValueByPath(source, path) {
  return path.split(".").reduce((value, segment) => {
    if (segment === "length") {
      if (Array.isArray(value) || typeof value === "string") {
        return value.length;
      }
      return 0;
    }
    return value?.[segment];
  }, source);
}

function setValueByPath(target, path, value) {
  const segments = path.split(".");
  let cursor = target;

  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index];
    if (cursor[segment] === undefined || cursor[segment] === null) {
      cursor[segment] = {};
    }
    cursor = cursor[segment];
  }

  cursor[segments[segments.length - 1]] = value;
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function updateConfigInputs() {
  configInputs.forEach((input) => {
    const path = input.dataset.configPath;
    if (!path || !state.config) {
      return;
    }

    const value = getValueByPath(state.config, path);
    if (input.type === "checkbox") {
      input.checked = Boolean(value);
    } else {
      input.value = value === null || value === undefined ? "" : String(value);
    }
  });
}

function collectConfigPayload() {
  const payload = deepClone(state.config);

  configInputs.forEach((input) => {
    const path = input.dataset.configPath;
    if (!path || input.readOnly || input.disabled) {
      return;
    }
    if (path.endsWith(".length")) {
      return;
    }

    let nextValue;
    if (input.type === "checkbox") {
      nextValue = input.checked;
    } else if (input.type === "number") {
      nextValue = input.value === "" ? 0 : Number(input.value);
    } else {
      nextValue = input.value;
    }

    setValueByPath(payload, path, nextValue);
  });

  return payload;
}

async function refreshStatus() {
  const status = await fetchJson("/api/status");

  setText("est-listener", `${status.est_listen_address}:${status.est_listen_port}`);
  setText("webui-listener", `${status.webui_listen_address}:${status.webui_listen_port}`);
  setText("pending-count", String(status.pending_enrollment_count));
  setText("issued-count", String(status.issued_enrollment_count));
  setText("systemd-unit", status.systemd_unit_name);
  setText("dashboard-systemd-active", status.systemd_active_state);
  setText("dashboard-systemd-enabled", status.systemd_enabled_state);
  setText("webui-auth-mode", status.webui_auth_mode);
  setText("webui-enabled", status.webui_enabled ? "yes" : "no");

  if (status.current_user) {
    setIdentity(status.current_user);
  }
}

async function refreshConfig() {
  const config = await fetchJson("/api/config");
  state.config = config;

  configOutput.textContent = JSON.stringify(config, null, 2);
  updateConfigInputs();
  applyConfigMode();
  applyConfigSectionCollapseState();
}

async function handleSaveConfig() {
  if (!canEditConfig() || !state.config) {
    showMessage("Only admin users can save configuration.", true);
    return;
  }

  try {
    clearMessage();
    const payload = collectConfigPayload();
    const savedConfig = await fetchJson("/api/config", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.config = savedConfig;
    configOutput.textContent = JSON.stringify(savedConfig, null, 2);
    updateConfigInputs();
    showMessage("Configuration saved.");
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to save configuration.", true);
  }
}

async function refreshRules() {
  const rules = await fetchJson("/api/rules");
  state.rules = rules;
  rulesDefaultAction.value = rules.default_action || "auto";
  renderRulesEditor(rules.rules || []);
}

async function refreshMe() {
  const me = await fetchJson("/api/me");
  setIdentity(me);
}

function setConfigMode(mode) {
  state.configMode = mode === "text" ? "text" : "gui";
  localStorage.setItem(CONFIG_MODE_STORAGE_KEY, state.configMode);
  applyConfigMode();
}

function applyConfigMode() {
  const useText = state.configMode === "text";
  configGui?.classList.toggle("hidden", useText);
  configOutput?.classList.toggle("hidden", !useText);

  configModeButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.configMode === state.configMode);
  });
}

function toggleConfigSection(sectionName) {
  if (!sectionName) {
    return;
  }

  const key = `${CONFIG_COLLAPSE_STORAGE_PREFIX}${sectionName}`;
  const isCollapsed = localStorage.getItem(key) === "true";
  localStorage.setItem(key, String(!isCollapsed));
  applyConfigSectionCollapseState();
}

function applyConfigSectionCollapseState() {
  document.querySelectorAll("[data-config-section]").forEach((section) => {
    const sectionName = section.dataset.configSection;
    const isCollapsed = localStorage.getItem(`${CONFIG_COLLAPSE_STORAGE_PREFIX}${sectionName}`) === "true";
    section.classList.toggle("collapsed", isCollapsed);
  });
}

function renderRulesEditor(rules) {
  if (!authorizationRulesContainer) {
    return;
  }

  if (!rules.length) {
    authorizationRulesContainer.innerHTML = `
      <div class="empty-state">
        No authorization rules are defined. Requests will use the selected default action.
      </div>
    `;
    return;
  }

  authorizationRulesContainer.innerHTML = rules
    .map((rule, index) => renderRuleCard(rule, index))
    .join("");

  authorizationRulesContainer.querySelectorAll("[data-rule-action]").forEach((button) => {
    button.disabled = !canModifyPolicy();
    button.addEventListener("click", () => handleRuleAction(button));
  });

  authorizationRulesContainer.querySelectorAll("[data-field]").forEach((field) => {
    field.disabled = !canModifyPolicy();
  });
}

function renderRuleCard(rule, index) {
  return `
    <article class="rule-card" data-rule-index="${index}">
      <div class="rule-card-header">
        <div>
          <h4>Rule ${index + 1}</h4>
          <p class="muted">Rules are evaluated in the order shown here.</p>
        </div>
        <div class="rule-card-actions">
          <button class="secondary-button table-button" type="button" data-rule-action="move-up" data-rule-index="${index}">
            Move up
          </button>
          <button class="secondary-button table-button" type="button" data-rule-action="move-down" data-rule-index="${index}">
            Move down
          </button>
          <button class="danger-button table-button" type="button" data-rule-action="delete" data-rule-index="${index}">
            Delete
          </button>
        </div>
      </div>

      <div class="rule-grid">
        <label class="field">
          <span>Rule name</span>
          <input type="text" data-field="name" value="${escapeAttribute(rule.name || "")}">
        </label>

        <label class="field">
          <span>Action</span>
          <select data-field="action">
            ${renderActionOptions(rule.action || "auto")}
          </select>
        </label>

        <label class="field">
          <span>Subject CN regex</span>
          <input type="text" data-field="match_subject_cn" placeholder="^device-.*$" value="${escapeAttribute(rule.match_subject_cn || "")}">
        </label>

        <label class="field">
          <span>Subject OU regex</span>
          <input type="text" data-field="match_subject_ou" placeholder="^Operations$" value="${escapeAttribute(rule.match_subject_ou || "")}">
        </label>

        <label class="field">
          <span>Subject O regex</span>
          <input type="text" data-field="match_subject_o" placeholder="^Example Corp$" value="${escapeAttribute(rule.match_subject_o || "")}">
        </label>

        <label class="field">
          <span>SAN DNS regex</span>
          <input type="text" data-field="match_san_dns" placeholder="\\.corp\\.example$" value="${escapeAttribute(rule.match_san_dns || "")}">
        </label>

        <label class="field">
          <span>SAN email regex</span>
          <input type="text" data-field="match_san_email" placeholder="@example\\.com$" value="${escapeAttribute(rule.match_san_email || "")}">
        </label>

        <label class="field">
          <span>Client cert issuer regex</span>
          <input type="text" data-field="match_client_cert_issuer" placeholder="CN=Demo CA" value="${escapeAttribute(rule.match_client_cert_issuer || "")}">
        </label>

        <label class="field">
          <span>Key type</span>
          <input type="text" data-field="match_key_type" placeholder="rsa | ecdsa | ed25519" value="${escapeAttribute(rule.match_key_type || "")}">
        </label>

        <label class="field">
          <span>Reject reason</span>
          <input type="text" data-field="reject_reason" placeholder="rejected by policy" value="${escapeAttribute(rule.reject_reason || "")}">
        </label>
      </div>
    </article>
  `;
}

function renderActionOptions(selectedValue) {
  return ["auto", "manual", "reject"]
    .map((value) => {
      const selected = value === selectedValue ? "selected" : "";
      return `<option value="${value}" ${selected}>${value}</option>`;
    })
    .join("");
}

function collectRulesPayload() {
  const cards = authorizationRulesContainer?.querySelectorAll(".rule-card") || [];
  const rules = Array.from(cards).map((card) => {
    const getFieldValue = (field) => {
      const element = card.querySelector(`[data-field="${field}"]`);
      return element?.value?.trim() || "";
    };

    return compactRule({
      name: getFieldValue("name"),
      match_subject_cn: getFieldValue("match_subject_cn"),
      match_subject_ou: getFieldValue("match_subject_ou"),
      match_subject_o: getFieldValue("match_subject_o"),
      match_san_dns: getFieldValue("match_san_dns"),
      match_san_email: getFieldValue("match_san_email"),
      match_client_cert_issuer: getFieldValue("match_client_cert_issuer"),
      match_key_type: getFieldValue("match_key_type"),
      action: getFieldValue("action") || "auto",
      reject_reason: getFieldValue("reject_reason"),
    });
  });

  return {
    default_action: rulesDefaultAction?.value || "auto",
    rules,
  };
}

function compactRule(rule) {
  return {
    name: rule.name || "",
    match_subject_cn: rule.match_subject_cn || null,
    match_subject_ou: rule.match_subject_ou || null,
    match_subject_o: rule.match_subject_o || null,
    match_san_dns: rule.match_san_dns || null,
    match_san_email: rule.match_san_email || null,
    match_client_cert_issuer: rule.match_client_cert_issuer || null,
    match_key_type: rule.match_key_type || null,
    action: rule.action || "auto",
    reject_reason: rule.reject_reason || null,
  };
}

function handleAddRule() {
  if (!canModifyPolicy()) {
    showMessage("Only admin users can modify authorization rules.", true);
    return;
  }

  const rules = state.rules?.rules ? [...state.rules.rules] : [];
  rules.push({
    name: "",
    match_subject_cn: null,
    match_subject_ou: null,
    match_subject_o: null,
    match_san_dns: null,
    match_san_email: null,
    match_client_cert_issuer: null,
    match_key_type: null,
    action: "manual",
    reject_reason: null,
  });
  renderRulesEditor(rules);
  state.rules = {
    default_action: rulesDefaultAction?.value || "auto",
    rules,
  };
}

function handleRuleAction(button) {
  if (!canModifyPolicy()) {
    showMessage("Only admin users can modify authorization rules.", true);
    return;
  }

  const index = Number(button.dataset.ruleIndex);
  const action = button.dataset.ruleAction;
  const currentRules = collectRulesPayload().rules;

  if (!Number.isInteger(index) || index < 0 || index >= currentRules.length) {
    return;
  }

  if (action === "delete") {
    currentRules.splice(index, 1);
  }

  if (action === "move-up" && index > 0) {
    [currentRules[index - 1], currentRules[index]] = [currentRules[index], currentRules[index - 1]];
  }

  if (action === "move-down" && index < currentRules.length - 1) {
    [currentRules[index + 1], currentRules[index]] = [currentRules[index], currentRules[index + 1]];
  }

  renderRulesEditor(currentRules);
  state.rules = {
    default_action: rulesDefaultAction?.value || "auto",
    rules: currentRules,
  };
}

async function handleSaveRules() {
  if (!canModifyPolicy()) {
    showMessage("Only admin users can save authorization rules.", true);
    return;
  }

  try {
    clearMessage();
    const payload = collectRulesPayload();
    const savedRules = await fetchJson("/api/rules", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.rules = savedRules;
    rulesDefaultAction.value = savedRules.default_action || "auto";
    renderRulesEditor(savedRules.rules || []);
    if (state.config) {
      state.config.enrollment = savedRules;
      await refreshConfig();
    }
    showMessage("Authorization rules saved.");
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to save authorization rules.", true);
  }
}

function renderPendingEnrollments(records) {
  if (!pendingEnrollmentsContainer) {
    return;
  }

  const actionButtons = canManageEnrollments()
    ? (record) => `
            <div class="inline-actions">
              <button
                class="primary-button table-button"
                type="button"
                data-pending-action="approve"
                data-operation="${escapeAttribute(record.operation)}"
                data-artifact-id="${escapeAttribute(record.artifact_id)}"
              >
                Approve
              </button>
              <button
                class="danger-button table-button"
                type="button"
                data-pending-action="reject"
                data-operation="${escapeAttribute(record.operation)}"
                data-artifact-id="${escapeAttribute(record.artifact_id)}"
              >
                Reject
              </button>
            </div>
      `
    : "";

  if (!records.length) {
    pendingEnrollmentsContainer.innerHTML = `
      <div class="empty-state">No pending enrollments were found.</div>
    `;
    return;
  }

  pendingEnrollmentsContainer.innerHTML = records
    .map((record) => {
      const rejectReason = record.reject_reason
        ? `<div><dt>reject reason</dt><dd>${escapeHtml(record.reject_reason)}</dd></div>`
        : "";

      return `
        <article class="stack-item">
          <div class="stack-item-header">
            <div>
              <h4>${escapeHtml(record.operation)} · ${escapeHtml(record.artifact_id)}</h4>
              <p class="muted">Matched rule: ${escapeHtml(record.matched_rule_name || "none")} · action: ${escapeHtml(record.action)}</p>
            </div>
            ${actionButtons(record)}
          </div>

          <div class="stack-item-meta">
            <dl class="kv-list">
              <div><dt>state</dt><dd>${escapeHtml(record.state)}</dd></div>
              <div><dt>retry after</dt><dd>${escapeHtml(String(record.retry_after_seconds))}s</dd></div>
              ${rejectReason}
            </dl>
            <dl class="kv-list">
              <div><dt>subject CN</dt><dd>${escapeHtml(record.context.subject_cn || "—")}</dd></div>
              <div><dt>subject OU</dt><dd>${escapeHtml(record.context.subject_ou || "—")}</dd></div>
              <div><dt>subject O</dt><dd>${escapeHtml(record.context.subject_o || "—")}</dd></div>
              <div><dt>SAN DNS</dt><dd>${escapeHtml((record.context.san_dns || []).join(", ") || "—")}</dd></div>
              <div><dt>SAN email</dt><dd>${escapeHtml((record.context.san_email || []).join(", ") || "—")}</dd></div>
              <div><dt>issuer</dt><dd>${escapeHtml(record.context.client_cert_issuer || "—")}</dd></div>
              <div><dt>key type</dt><dd>${escapeHtml(record.context.key_type || "—")}</dd></div>
            </dl>
          </div>
        </article>
      `;
    })
    .join("");

  pendingEnrollmentsContainer.querySelectorAll("[data-pending-action]").forEach((button) => {
    button.addEventListener("click", () => void handlePendingEnrollmentAction(button));
  });
}

async function refreshPendingEnrollments() {
  const records = await fetchJson("/api/enrollment/pending");
  state.pendingEnrollments = records;
  renderPendingEnrollments(records);
}

async function handlePendingEnrollmentAction(button) {
  const action = button.dataset.pendingAction;
  const operation = button.dataset.operation;
  const artifactId = button.dataset.artifactId;

  if (!action || !operation || !artifactId) {
    return;
  }

  if (!canManageEnrollments()) {
    showMessage("Only admin users can act on pending enrollments.", true);
    return;
  }

  try {
    clearMessage();

    if (action === "approve") {
      await fetchJson(
        `/api/enrollment/pending/${encodeURIComponent(operation)}/${encodeURIComponent(artifactId)}/approve`,
        { method: "POST" }
      );
      showMessage(`Approved pending enrollment ${artifactId}.`);
    }

    if (action === "reject") {
      const reason = window.prompt(
        `Reject pending enrollment ${artifactId}. Enter a reason:`,
        "rejected by administrator"
      );
      if (reason === null) {
        return;
      }

      await fetchJson(
        `/api/enrollment/pending/${encodeURIComponent(operation)}/${encodeURIComponent(artifactId)}/reject`,
        {
          method: "POST",
          body: JSON.stringify({ reason }),
        }
      );
      showMessage(`Rejected pending enrollment ${artifactId}.`);
    }

    await Promise.all([refreshPendingEnrollments(), refreshStatus()]);
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to update pending enrollment.", true);
  }
}

function renderEnrollmentHistory(records) {
  if (!enrollmentHistoryContainer) {
    return;
  }

  if (!records.length) {
    enrollmentHistoryContainer.innerHTML = `
      <div class="empty-state">No issued enrollment artifacts were found.</div>
    `;
    return;
  }

  enrollmentHistoryContainer.innerHTML = records
    .map(
      (record) => `
        <article class="stack-item">
          <div class="stack-item-header">
            <div>
              <h4>${escapeHtml(record.operation)} · ${escapeHtml(record.artifact_id)}</h4>
              <p class="muted">Persisted EST enrollment artifact paths.</p>
            </div>
          </div>
          <dl class="kv-list">
            <div><dt>CSR path</dt><dd>${escapeHtml(record.csr_path || "—")}</dd></div>
            <div><dt>certificate path</dt><dd>${escapeHtml(record.certificate_path || "—")}</dd></div>
          </dl>
        </article>
      `
    )
    .join("");
}

async function refreshEnrollmentHistory() {
  const records = await fetchJson("/api/enrollment/history");
  state.enrollmentHistory = records;
  renderEnrollmentHistory(records);
}

function renderUsersTable() {
  if (!usersTableBody) {
    return;
  }

  if (!state.users.length) {
    usersTableBody.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No users found.</td>
      </tr>
    `;
    return;
  }

  usersTableBody.innerHTML = state.users
    .map((user) => {
      const enabledLabel = user.enabled ? "yes" : "no";
      const toggleLabel = user.enabled ? "Disable" : "Enable";
      const manageActions = canManageUsers()
        ? `
          <button class="secondary-button table-button" data-action="reset-password" data-username="${escapeAttribute(user.username)}">
            Set password
          </button>
        `
        : `<span class="muted">read-only</span>`;

      const roleActions = canManageUsers()
        ? ["auditor", "admin", "super-admin"]
            .filter((role) => role !== user.role)
            .map(
              (role) => `
                <button class="secondary-button table-button" data-action="set-role" data-username="${escapeAttribute(user.username)}" data-role="${escapeAttribute(role)}">
                  Make ${escapeHtml(role)}
                </button>
              `
            )
            .join("")
        : `<span class="muted">read-only</span>`;

      const lifecycleActions = canManageUsers()
        ? `
            <button class="secondary-button table-button" data-action="toggle-enabled" data-username="${escapeAttribute(user.username)}" data-enabled="${String(!user.enabled)}">
              ${toggleLabel}
            </button>
            <button class="danger-button table-button" data-action="delete-user" data-username="${escapeAttribute(user.username)}">
              Delete
            </button>
          `
        : "";

      return `
        <tr>
          <td>${escapeHtml(user.username)}</td>
          <td><span class="role-badge">${escapeHtml(user.role)}</span></td>
          <td>${enabledLabel}</td>
          <td>${manageActions}</td>
          <td class="table-actions">
            ${roleActions}
            ${lifecycleActions}
          </td>
        </tr>
      `;
    })
    .join("");

  usersTableBody.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => void handleUserAction(button));
  });
}

async function refreshUsers() {
  state.users = await fetchJson("/api/users");
  renderUsersTable();
}

async function handleCreateUser(event) {
  event.preventDefault();

  const username = document.getElementById("create-username").value.trim();
  const password = document.getElementById("create-password").value;
  const role = document.getElementById("create-role").value;

  if (!username || !password) {
    showMessage("Username and password are required.", true);
    return;
  }

  try {
    clearMessage();
    await fetchJson("/api/users", {
      method: "POST",
      body: JSON.stringify({ username, password, role }),
    });
    createUserForm.reset();
    document.getElementById("create-role").value = "auditor";
    await refreshUsers();
    showMessage(`User ${username} created.`);
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to create user.", true);
  }
}

async function handleChangeOwnPassword(event) {
  event.preventDefault();

  const currentPassword = document.getElementById("current-password").value;
  const newPassword = document.getElementById("new-password").value;

  if (!currentPassword || !newPassword) {
    showMessage("Both current and new password are required.", true);
    return;
  }

  try {
    clearMessage();
    await fetchJson("/api/account/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    changePasswordForm.reset();
    showMessage("Your password was updated.");
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to change password.", true);
  }
}

async function handleUserAction(button) {
  const action = button.dataset.action;
  const username = button.dataset.username;

  try {
    clearMessage();

    if (action === "reset-password") {
      const password = window.prompt(`Enter a new password for ${username}:`);
      if (!password) {
        return;
      }

      await fetchJson(`/api/users/${encodeURIComponent(username)}/password`, {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      showMessage(`Password updated for ${username}.`);
    }

    if (action === "set-role") {
      await fetchJson(`/api/users/${encodeURIComponent(username)}/role`, {
        method: "POST",
        body: JSON.stringify({ role: button.dataset.role }),
      });
      showMessage(`Role updated for ${username}.`);
    }

    if (action === "toggle-enabled") {
      await fetchJson(`/api/users/${encodeURIComponent(username)}/enabled`, {
        method: "POST",
        body: JSON.stringify({ enabled: button.dataset.enabled === "true" }),
      });
      showMessage(`Enabled state updated for ${username}.`);
    }

    if (action === "delete-user") {
      const confirmed = window.confirm(`Delete user ${username}?`);
      if (!confirmed) {
        return;
      }

      await fetchJson(`/api/users/${encodeURIComponent(username)}/delete`, {
        method: "POST",
      });
      showMessage(`User ${username} deleted.`);
    }

    await refreshUsers();
  } catch (error) {
    console.error(error);
    showMessage(error.message || "User action failed.", true);
  }
}

function renderSystemd(status) {
  state.systemd = status;

  setText("systemd-detail-unit", status.unit_name);
  setText("systemd-detail-description", status.description || "—");
  setText("systemd-detail-active-state", status.active_state);
  setText("systemd-detail-sub-state", status.sub_state);
  setText("systemd-detail-enabled-state", status.enabled_state);
  setText("systemd-detail-main-pid", status.main_pid);
  setText("systemd-detail-tasks-current", status.tasks_current);
  setText("systemd-detail-memory-current", formatBytes(status.memory_current));

  setText("systemd-active-pill", `active: ${status.active_state}`);
  setText("systemd-enabled-pill", `enabled: ${status.enabled_state}`);
  setText("systemd-load-pill", `load: ${status.load_state}`);

  const journalOutput = document.getElementById("systemd-journal-output");
  if (journalOutput) {
    journalOutput.textContent = (status.recent_journal || []).join("\n") || "No journal lines available.";
  }
}

async function refreshSystemdStatus() {
  const status = await fetchJson("/api/systemd/status");
  renderSystemd(status);
}

async function handleSystemdAction(action) {
  if (!action) {
    return;
  }

  if (!canManageSystemd()) {
    showInlineNotice(systemdActionResult, "Only admin users can run systemd actions.", true);
    return;
  }

  try {
    clearInlineNotice(systemdActionResult);
    systemdActionButtons.forEach((button) => {
      button.disabled = true;
    });

    const result = await fetchJson(`/api/systemd/${encodeURIComponent(action)}`, {
      method: "POST",
    });

    showInlineNotice(
      systemdActionResult,
      result.output
        ? `${result.action} completed${result.success ? "" : " with errors"}: ${result.output}`
        : `${result.action} completed.`,
      !result.success
    );

    await Promise.all([refreshSystemdStatus(), refreshStatus()]);
  } catch (error) {
    console.error(error);
    showInlineNotice(systemdActionResult, error.message || "systemd action failed.", true);
  } finally {
    systemdActionButtons.forEach((button) => {
      button.disabled = false;
    });
  }
}

async function refreshTrustedCa() {
  const certificates = await fetchJson("/api/certstore/ca");
  state.trustedCa = certificates;
  renderTrustedCaTable();
}

async function refreshLeafCertificates() {
  const certificates = await fetchJson("/api/certstore/leaf");
  state.leafCertificates = certificates;
  renderLeafCertificatesTable();
}

function renderTrustedCaTable() {
  if (!trustedCaTableBody) {
    return;
  }

  if (!state.trustedCa.length) {
    trustedCaTableBody.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No Trusted CA certificates loaded.</td>
      </tr>
    `;
    return;
  }

  trustedCaTableBody.innerHTML = state.trustedCa
    .map(
      (certificate) => `
        <tr>
          <td>${escapeHtml(certificate.subject)}</td>
          <td>${escapeHtml(certificate.issuer)}</td>
          <td>${escapeHtml(certificate.not_after)}</td>
          <td><code>${escapeHtml(truncateFingerprint(certificate.fingerprint))}</code></td>
          <td class="table-actions">
            <button class="secondary-button table-button" type="button" data-certificate-action="view-trusted-ca" data-fingerprint="${escapeAttribute(certificate.fingerprint)}">
              View
            </button>
            ${canManageCertificates() ? `<button class="danger-button table-button" type="button" data-certificate-action="delete-trusted-ca" data-fingerprint="${escapeAttribute(certificate.fingerprint)}">
              Delete
            </button>` : ""}
          </td>
        </tr>
      `
    )
    .join("");

  trustedCaTableBody.querySelectorAll("[data-certificate-action]").forEach((button) => {
    button.addEventListener("click", () => void handleCertificateAction(button));
  });
}

function renderLeafCertificatesTable() {
  if (!leafCertificatesTableBody) {
    return;
  }

  if (!state.leafCertificates.length) {
    leafCertificatesTableBody.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No leaf certificates loaded.</td>
      </tr>
    `;
    return;
  }

  leafCertificatesTableBody.innerHTML = state.leafCertificates
    .map(
      (certificate) => `
        <tr>
          <td>${escapeHtml(certificate.subject)}</td>
          <td>${escapeHtml(certificate.issuer)}</td>
          <td>${escapeHtml(certificate.not_after)}</td>
          <td><code>${escapeHtml(truncateFingerprint(certificate.fingerprint))}</code></td>
          <td class="table-actions">
            <button class="secondary-button table-button" type="button" data-certificate-action="view-leaf" data-fingerprint="${escapeAttribute(certificate.fingerprint)}">
              View
            </button>
            ${canManageCertificates() ? `<button class="danger-button table-button" type="button" data-certificate-action="delete-leaf" data-fingerprint="${escapeAttribute(certificate.fingerprint)}">
              Delete
            </button>` : ""}
          </td>
        </tr>
      `
    )
    .join("");

  leafCertificatesTableBody.querySelectorAll("[data-certificate-action]").forEach((button) => {
    button.addEventListener("click", () => void handleCertificateAction(button));
  });
}

async function handleUploadTrustedCa(event) {
  event.preventDefault();

  if (!canManageCertificates()) {
    showInlineNotice(trustedCaInlineNotice, "Only admin users can load Trusted CA certificates.", true);
    return;
  }

  const fileInput = document.getElementById("trusted-ca-file");
  const file = fileInput?.files?.[0];
  if (!file) {
    showInlineNotice(trustedCaInlineNotice, "Select a PEM CA certificate first.", true);
    return;
  }

  try {
    clearInlineNotice(trustedCaInlineNotice);
    const contentBase64 = await readFileAsBase64(file);
    await fetchJson("/api/certstore/ca", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        content_base64: contentBase64,
      }),
    });
    uploadTrustedCaForm.reset();
    await refreshTrustedCa();
    showInlineNotice(trustedCaInlineNotice, "Trusted CA loaded.");
  } catch (error) {
    console.error(error);
    showInlineNotice(trustedCaInlineNotice, error.message || "Failed to load Trusted CA.", true);
  }
}

async function handleUploadLeafCertificate(event) {
  event.preventDefault();

  if (!canManageCertificates()) {
    showInlineNotice(leafCertificatesInlineNotice, "Only admin users can load leaf certificates.", true);
    return;
  }

  const fileInput = document.getElementById("leaf-certificate-file");
  const passwordInput = document.getElementById("leaf-certificate-password");
  const file = fileInput?.files?.[0];

  if (!file) {
    showInlineNotice(leafCertificatesInlineNotice, "Select a P12 file first.", true);
    return;
  }

  try {
    clearInlineNotice(leafCertificatesInlineNotice);
    const contentBase64 = await readFileAsBase64(file);
    await fetchJson("/api/certstore/leaf", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        password: passwordInput?.value || "",
        content_base64: contentBase64,
      }),
    });
    uploadLeafCertificateForm.reset();
    await refreshLeafCertificates();
    showInlineNotice(leafCertificatesInlineNotice, "Leaf certificate loaded.");
  } catch (error) {
    console.error(error);
    showInlineNotice(
      leafCertificatesInlineNotice,
      error.message || "Failed to load leaf certificate.",
      true
    );
  }
}

async function handleCertificateAction(button) {
  const action = button.dataset.certificateAction;
  const fingerprint = button.dataset.fingerprint;

  if (!action || !fingerprint) {
    return;
  }

  if (action.startsWith("delete-") && !canManageCertificates()) {
    showInlineNotice(
      action.includes("trusted") ? trustedCaInlineNotice : leafCertificatesInlineNotice,
      "Only admin users can delete certificates.",
      true
    );
    return;
  }

  try {
    if (action === "view-trusted-ca") {
      const detail = await fetchJson(`/api/certstore/ca/${encodeURIComponent(fingerprint)}`);
      openCertificateDetail(detail, "Trusted CA Certificate");
      return;
    }

    if (action === "view-leaf") {
      const detail = await fetchJson(`/api/certstore/leaf/${encodeURIComponent(fingerprint)}`);
      openCertificateDetail(detail, "Leaf Certificate");
      return;
    }

    if (action === "delete-trusted-ca") {
      const confirmed = window.confirm("Delete this Trusted CA certificate?");
      if (!confirmed) {
        return;
      }
      await fetchJson(`/api/certstore/ca/${encodeURIComponent(fingerprint)}`, {
        method: "DELETE",
      });
      await refreshTrustedCa();
      showInlineNotice(trustedCaInlineNotice, "Trusted CA deleted.");
      return;
    }

    if (action === "delete-leaf") {
      const confirmed = window.confirm("Delete this leaf certificate?");
      if (!confirmed) {
        return;
      }
      await fetchJson(`/api/certstore/leaf/${encodeURIComponent(fingerprint)}`, {
        method: "DELETE",
      });
      await refreshLeafCertificates();
      showInlineNotice(leafCertificatesInlineNotice, "Leaf certificate deleted.");
    }
  } catch (error) {
    console.error(error);
    const targetNotice =
      action.includes("trusted") ? trustedCaInlineNotice : leafCertificatesInlineNotice;
    showInlineNotice(targetNotice, error.message || "Certificate operation failed.", true);
  }
}

function openCertificateDetail(detail, title) {
  if (!certificateDetailDrawer || !certificateDetailBody) {
    return;
  }

  certificateDetailTitle.textContent = title;
  certificateDetailSubtitle.textContent = detail.original_filename || detail.fingerprint;
  certificateDetailBody.innerHTML = renderCertificateDetail(detail);
  certificateDetailDrawer.classList.add("open");
  certificateDetailDrawer.setAttribute("aria-hidden", "false");
  certificateDetailBackdrop?.classList.remove("hidden");
  state.certificateDetailOpen = true;
}

function closeCertificateDetail() {
  certificateDetailDrawer?.classList.remove("open");
  certificateDetailDrawer?.setAttribute("aria-hidden", "true");
  certificateDetailBackdrop?.classList.add("hidden");
  state.certificateDetailOpen = false;
}

function renderCertificateDetail(detail) {
  const sections = [
    renderDecodedCertificateSection("Leaf Certificate", detail.leaf),
    ...(detail.chain || []).map((certificate, index) =>
      renderDecodedCertificateSection(`Chain Certificate ${index + 1}`, certificate)
    ),
  ];

  return `
    <div class="certificate-detail-stack">
      <div class="certificate-summary-banner">
        <strong>Fingerprint:</strong> <code>${escapeHtml(detail.fingerprint)}</code>
      </div>
      ${sections.join("")}
    </div>
  `;
}

function renderDecodedCertificateSection(title, certificate) {
  return `
    <section class="certificate-detail-section">
      <h4>${escapeHtml(title)}</h4>
      <dl class="kv-list">
        <div><dt>subject</dt><dd>${escapeHtml(certificate.subject)}</dd></div>
        <div><dt>issuer</dt><dd>${escapeHtml(certificate.issuer)}</dd></div>
        <div><dt>serial number</dt><dd>${escapeHtml(certificate.serial_number)}</dd></div>
        <div><dt>not before</dt><dd>${escapeHtml(certificate.not_before)}</dd></div>
        <div><dt>not after</dt><dd>${escapeHtml(certificate.not_after)}</dd></div>
        <div><dt>SHA-256</dt><dd><code>${escapeHtml(certificate.fingerprint_sha256)}</code></dd></div>
        <div><dt>key algorithm</dt><dd>${escapeHtml(certificate.key_algorithm)}</dd></div>
        <div><dt>key bits</dt><dd>${escapeHtml(String(certificate.key_bits))}</dd></div>
        <div><dt>SAN DNS</dt><dd>${escapeHtml((certificate.san_dns || []).join(", ") || "—")}</dd></div>
        <div><dt>SAN email</dt><dd>${escapeHtml((certificate.san_email || []).join(", ") || "—")}</dd></div>
      </dl>
      <pre class="code-block">${escapeHtml(certificate.pem || "")}</pre>
    </section>
  `;
}

function truncateFingerprint(fingerprint) {
  if (!fingerprint || fingerprint.length <= 18) {
    return fingerprint || "—";
  }
  return `${fingerprint.slice(0, 10)}…${fingerprint.slice(-8)}`;
}

function openHelp(viewName) {
  renderHelp(viewName || state.activeView);
  state.helpOpen = true;
  helpDrawer?.classList.add("open");
  helpDrawer?.setAttribute("aria-hidden", "false");
  helpBackdrop?.classList.remove("hidden");
}

function closeHelp() {
  state.helpOpen = false;
  helpDrawer?.classList.remove("open");
  helpDrawer?.setAttribute("aria-hidden", "true");
  helpBackdrop?.classList.add("hidden");
}

function renderHelp(viewName) {
  const normalizedView = views[viewName] ? viewName : state.activeView;
  const template = document.getElementById(`help-template-${normalizedView}`);
  const meta = views[normalizedView];

  helpDrawerTitle.textContent = meta?.title ? `${meta.title} Help` : "Help & Docs";
  helpDrawerSubtitle.textContent = meta?.subtitle || "Quick-reference guidance for the active view.";
  helpDrawerBody.innerHTML = template ? template.innerHTML : "<p>No help is available for this view.</p>";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#96;");
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const [, base64] = result.split(",", 2);
      if (!base64) {
        reject(new Error("Failed to encode file as base64."));
        return;
      }
      resolve(base64);
    };
    reader.onerror = () => reject(new Error("Failed to read the selected file."));
    reader.readAsDataURL(file);
  });
}

async function refreshAll() {
  try {
    clearMessage();
    await refreshMe();
    await Promise.all([
      refreshStatus(),
      refreshConfig(),
      refreshRules(),
      refreshPendingEnrollments(),
      refreshEnrollmentHistory(),
      refreshSystemdStatus(),
      refreshUsers(),
      refreshTrustedCa(),
      refreshLeafCertificates(),
    ]);
  } catch (error) {
    console.error(error);
    showMessage(error.message || "Failed to load WebUI data.", true);
  }
}

applyConfigMode();
applyConfigSectionCollapseState();
setActiveView(state.activeView);
void refreshAll();