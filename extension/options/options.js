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
  const email = license.email || auth.user?.email || "Not connected";

  document.getElementById("install-id").textContent = state.installId || "-";
  document.getElementById("account-email").textContent = email;
  document.getElementById("status").textContent = license.is_paid
    ? (license.plan_type === "annual" ? "Paid (Annual)" : "Paid (Monthly)")
    : license.trial_active
      ? "15-Day Free Trial"
      : "Free";
  document.getElementById("protection-level").textContent = license.is_paid || license.trial_active
    ? "All 17 checks running"
    : "2 of 17 checks running — link safety and password fields";

  const pill = document.getElementById("status-pill");
  if (license.is_paid) {
    pill.textContent = "Paid Active";
    pill.className = "pill success";
    setMsg("status-msg", "Full protection is active on this install.", "success");
  } else if (license.trial_active) {
    pill.textContent = "Trial Active";
    pill.className = "pill success";
    const remaining = Math.max(0, Number(license.days_remaining || 0));
    const message = remaining <= 1
      ? "Your free trial is active. 1 day remains before payment is required."
      : `Your free trial is active. ${remaining} days remain before payment is required.`;
    setMsg("status-msg", message, "success");
  } else {
    pill.textContent = "Free";
    pill.className = "pill neutral";
    setMsg("status-msg", "Your trial has ended. Link safety and password-field checks are still running and do not expire.", "");
  }

  const signedOut = !auth.user?.email;
  document.getElementById("open-billing").style.display = license.is_paid ? "none" : "";
  document.getElementById("logout").style.display = signedOut ? "none" : "";

  /* The account card is shown to anyone who is not signed in on an unpaid
     install. That covers three cases with one rule: the mid-trial ask (the
     install is anonymous and needs_account is deliberately false), the
     post-trial ask, and signing back in after a logout. Gating this on
     needs_account would hide the card during the trial, which is exactly
     when we now do the asking. */
  document.getElementById("auth-card").style.display =
    signedOut && !license.is_paid ? "" : "none";

  /* An account is never required to pay — checkout is keyed by install id.
     It is only the way to carry a trial or a plan to another browser, so it
     is framed as optional in both states. */
  const trialOver = !license.is_paid && !license.trial_active;
  document.getElementById("auth-title").textContent = trialOver ? "Add an account" : "Keep your trial";
  document.getElementById("auth-pill").textContent = "Optional";
  document.getElementById("auth-copy").textContent = trialOver
    ? "Not needed to subscribe. Add an email if you want your plan to follow you to a reinstall or a second browser. We store your email and whether your plan is trial or paid. Nothing about the pages you visit."
    : "Add an email so your trial survives a reinstall or a second browser. We store your email and whether your plan is trial or paid. Nothing about the pages you visit.";

  /* The checkout card is for every ended, unpaid trial — with or without an
     account. needs_payment alone is only true for linked installs, which
     hid the offer from exactly the anonymous users who make up the funnel.
     The offline-at-install fallback licence has none of these set, so it
     does not get a "Trial Ended" card for a trial that has not started. */
  const trialEnded = trialOver && !!(license.trial_expires_at || license.needs_payment || license.needs_account);
  document.getElementById("payment-card").style.display = trialEnded ? "" : "none";
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
  if (!silent) btn.textContent = "Checking...";
  try {
    const resp = await chrome.runtime.sendMessage({ type: "REFRESH_LICENSE_STATE" });
    state.license = resp?.license || {};
    await loadState();
  } finally {
    if (!silent) btn.textContent = previousText || "Refresh Status";
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
  setMsg("auth-msg", "Logged out.", "success");
  await loadState();
});

document.getElementById("save-name").addEventListener("click", async () => {
  const name = document.getElementById("user-name").value.trim();
  await chrome.runtime.sendMessage({ type: "SET_USER_NAME", name });
  const btn = document.getElementById("save-name");
  btn.textContent = "Saved!";
  setTimeout(() => { btn.textContent = "Save Name"; }, 1500);
});

window.addEventListener("focus", () => {
  if (state.license?.needs_payment) queueSilentRefresh();
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.license?.needs_payment) {
    queueSilentRefresh();
  }
});

applyTabState();
loadState();
