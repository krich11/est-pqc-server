const views = {
  dashboard: {
    title: "Dashboard",
    subtitle: "Server health, enrollment state, and administrative actions.",
  },
  configuration: {
    title: "Configuration",
    subtitle: "Current effective runtime configuration.",
  },
  authorization: {
    title: "Authorization Rules",
    subtitle: "Per-enrollment policy rules and default behavior.",
  },
  queue: {
    title: "Pending Enrollments",
    subtitle: "Deferred EST requests awaiting administrator action.",
  },
  history: {
    title: "Enrollment History",
    subtitle: "Completed enrollment artifacts and issuance history.",
  },
  systemd: {
    title: "systemd",
    subtitle: "Service status and controlled lifecycle actions.",
  },
};

const pageTitle = document.getElementById("page-title");
const pageSubtitle = document.getElementById("page-subtitle");
const messageBanner = document.getElementById("message-banner");
const configOutput = document.getElementById("config-output");

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});

document
  .getElementById("refresh-button")
  .addEventListener("click", () => void refreshAll());

function setActiveView(viewName) {
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

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
    },
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json();
}

async function refreshStatus() {
  const status = await fetchJson("/api/status");

  document.getElementById("est-listener").textContent =
    `${status.est_listen_address}:${status.est_listen_port}`;
  document.getElementById("webui-listener").textContent =
    `${status.webui_listen_address}:${status.webui_listen_port}`;
  document.getElementById("pending-count").textContent =
    String(status.pending_enrollment_count);
  document.getElementById("issued-count").textContent =
    String(status.issued_enrollment_count);
  document.getElementById("systemd-unit").textContent = status.systemd_unit_name;
  document.getElementById("webui-auth-mode").textContent = status.webui_auth_mode;
  document.getElementById("webui-enabled").textContent = status.webui_enabled ? "yes" : "no";
}

async function refreshConfig() {
  const config = await fetchJson("/api/config");
  configOutput.textContent = JSON.stringify(config, null, 2);
}

async function refreshAll() {
  try {
    clearMessage();
    await Promise.all([refreshStatus(), refreshConfig()]);
  } catch (error) {
    console.error(error);
    showMessage("Failed to load WebUI data.", true);
  }
}

void refreshAll();