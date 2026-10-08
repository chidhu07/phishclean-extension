const state = {
  mode: "signup",
  installId: "",
  license: null,
  auth: null
};

function setMsg(id, text, type = "") {
  const el = document.getElementById(id);
  el.textContent = text || "";
  el.className = "inline-msg" + (type ? " " + type : "");
}

function applyTabState() {
  const signupActive = state.mode === "signup";
  document.getElementById("tab-signup").classList.toggle("active", signupActive);
  document.getElementById("tab-login").classList.toggle("active", !signupActive);
  document.getElementById("full-name-field").style.display = signupActive ? "" : "none";
  document.getElementById("forgot-password").style.display = signupActive ? "none" : "";
  document.getElementById("auth-submit").textContent = signupActive ? "Create account" : "Sign in";
}

function renderStatusCard() {
  const license = state.license || {};
  const auth = state.auth || {};
  const email = license.email || auth.user?.email || "None";

  document.getElementById("install-id").textContent = state.installId || "-";
  document.getElementById("account-email").textContent = email;
  document.getElementById("status").textContent = license.is_paid
    ? (license.plan_type === "lifetime" ? "Pro, lifetime"
      : license.plan_type === "annual" ? "Pro, annual" : "Pro, monthly")
    : license.trial_active
      ? "Free trial"
      : "Free";
  /* Price labels come from the server by IP country (rupees for India). */
  if (license.pricing) {
    document.getElementById("pay-prices").textContent = `${license.pricing.monthly} or ${license.pricing.annual}`;
  }
  document.getElementById("protection-level").textContent = license.is_paid || license.trial_active
    ? "All checks on"
    : "Core checks only";

  const pill = document.getElementById("status-pill");
  if (license.is_paid) {
    pill.textContent = "Pro";
    pill.className = "pill success";
    setMsg("status-msg", "");
  } else if (license.trial_active) {
    pill.textContent = "Trial";
    pill.className = "pill success";
    const remaining = Math.max(0, Number(license.days_remaining || 0));
    setMsg("status-msg", remaining <= 1 ? "Last day of your free trial." : `${remaining} days left in your free trial.`);
  } else {
    pill.textContent = "Free";
    pill.className = "pill neutral";
    setMsg("status-msg", "");
  }

  const signedOut = !auth.user?.email;
  document.getElementById("logout").style.display = signedOut ? "none" : "";

  /* The account card is shown to anyone who is not signed in: mid-trial,
     after the trial, after a logout, and on a paid install. It used to be
     hidden once paid, but a paid install with no account loses its plan on
     reinstall; the account is the only thing that carries it (signing in
     copies the install's payment onto the account). */
  document.getElementById("auth-card").style.display = signedOut ? "" : "none";

  /* An account is never required to pay — checkout is keyed by install id.
     It is only the way to carry a trial or a plan to another browser, so it
     is framed as optional in every state. */
  const trialOver = !license.is_paid && !license.trial_active;
  document.getElementById("auth-title").textContent = license.is_paid
    ? "Keep your plan"
    : trialOver ? "Add an account" : "Keep your trial";
  document.getElementById("auth-pill").textContent = "Optional";
  document.getElementById("auth-copy").textContent = license.is_paid
    ? "Your plan is tied to this browser. Add an email, or sign in, so it survives a reinstall and works on your other browsers. We store your email and whether your plan is trial or paid. Nothing about the pages you visit."
    : trialOver
      ? "Not needed to subscribe. Add an email if you want your plan to follow you to a reinstall or a second browser. We store your email and whether your plan is trial or paid. Nothing about the pages you visit."
      : "Add an email so your trial survives a reinstall or a second browser. We store your email and whether your plan is trial or paid. Nothing about the pages you visit.";

  /* The checkout card is for every ended, unpaid trial — with or without an
     account. needs_payment alone is only true for linked installs, which
     hid the offer from exactly the anonymous users who make up the funnel.
     The offline-at-install fallback licence has none of these set, so it
     does not get a "Trial Ended" card for a trial that has not started. */
  const trialEnded = trialOver && !!(license.trial_expires_at || license.needs_payment || license.needs_account);
  document.getElementById("payment-card").style.display = trialEnded ? "" : "none";

  /* One upgrade button per screen: when the checkout card is showing, it
     owns the offer and the status card stays quiet. */
  document.getElementById("open-billing").style.display = license.is_paid || trialEnded ? "none" : "";

  document.getElementById("intro").textContent = license.is_paid
    ? "Every check is running on every page you open."
    : license.trial_active
      ? "Every check is running during your free trial. After it ends, reported-phishing blocking, link safety and password checks stay on for free."
      : "Reported-phishing blocking, link safety and password checks are running on every page you open. No account needed.";
}

async function loadState() {
  const resp = await chrome.runtime.sendMessage({ type: "GET_LICENSE_STATE" });
  state.installId = resp?.install_id || "";
  state.license = resp?.license || {};
  state.auth = resp?.auth || null;
  document.getElementById("user-name").value = (await chrome.runtime.sendMessage({ type: "GET_USER_NAME" }))?.name || "";
  renderStatusCard();
}

async function refreshState() {
  return refreshStateInternal(false);
}

async function refreshStateInternal(silent) {
  const btn = document.getElementById("refresh");
  const previousText = btn.textContent;
  if (!silent) btn.textContent = "Checking\u2026";
  try {
    const resp = await chrome.runtime.sendMessage({ type: "REFRESH_LICENSE_STATE" });
    state.license = resp?.license || {};
    await loadState();
  } finally {
    if (!silent) btn.textContent = previousText || "Refresh";
  }
}

let refreshTimer = null;
function queueSilentRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    refreshStateInternal(true).catch(() => {});
  }, 400);
}

async function submitAuth() {
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value.trim();
  const fullName = document.getElementById("auth-name").value.trim();
  if (!email || !password) {
    setMsg("auth-msg", "Email and password are required.", "error");
    return;
  }

  const btn = document.getElementById("auth-submit");
  btn.textContent = state.mode === "signup" ? "Creating..." : "Signing in...";
  btn.disabled = true;
  setMsg("auth-msg", "");

  try {
    const resp = await chrome.runtime.sendMessage({
      type: "AUTH_WITH_ACCOUNT",
      mode: state.mode,
      email,
      password,
      fullName
    });
    if (!resp?.ok) throw new Error(resp?.error || "Authentication failed");

    setMsg("auth-msg", state.mode === "signup" ? "Account created. Your trial is now tied to this email, not just this browser." : "Signed in. Your plan status has been refreshed.", "success");
    await loadState();
  } catch (error) {
    setMsg("auth-msg", error?.message || "Authentication failed.", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = state.mode === "signup" ? "Create account" : "Sign in";
  }
}

document.getElementById("tab-signup").addEventListener("click", () => {
  state.mode = "signup";
  applyTabState();
});

document.getElementById("tab-login").addEventListener("click", () => {
  state.mode = "login";
  applyTabState();
});

document.getElementById("auth-submit").addEventListener("click", submitAuth);
document.getElementById("refresh").addEventListener("click", refreshState);

document.getElementById("open-billing").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "OPEN_PAYMENT" });
});

document.getElementById("pay-now").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "OPEN_PAYMENT" });
});

document.getElementById("logout").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "LOGOUT_ACCOUNT" });
  setMsg("auth-msg", "Signed out.", "success");
  await loadState();
});

document.getElementById("save-name").addEventListener("click", async () => {
  const name = document.getElementById("user-name").value.trim();
  await chrome.runtime.sendMessage({ type: "SET_USER_NAME", name });
  const btn = document.getElementById("save-name");
  btn.textContent = "Saved";
  setTimeout(() => { btn.textContent = "Save"; }, 1500);
});

/* Recheck on return while unpaid. This used to require needs_payment, but an
   anonymous install is needs_account instead, so someone who paid without an
   account came back to a stale "Free" until the next 6-hour check. */
window.addEventListener("focus", () => {
  if (!state.license?.is_paid) queueSilentRefresh();
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !state.license?.is_paid) {
    queueSilentRefresh();
  }
});

/* The background refreshes the license when a checkout completes; show it
   the moment it lands. */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.phishclean_license) loadState();
});

applyTabState();
loadState();
