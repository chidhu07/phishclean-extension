/* PhishClean clipboard hook — injected into page context as web_accessible_resource,
   only on pages that show a robot-check or keyboard-shortcut cue (see
   detectFakeCaptcha in contentScript.js). Reports text the page itself writes
   to the clipboard, so a fake CAPTCHA that copies a command can be caught
   before it is pasted. The text goes to the content script by nonce-
   authenticated postMessage and nowhere else; it is never stored or sent. */
(() => {
  if (window.__phishcleanClipboardHook) return;
  window.__phishcleanClipboardHook = true;
  const nc = document.currentScript?.dataset?.nonce || "";
  const report = (text) => {
    try {
      if (typeof text !== "string" || !text.trim()) return;
      window.postMessage({ source: "phishclean", type: "CLIPBOARD_WRITE", nonce: nc, text: text.slice(0, 4000) }, "*");
    } catch { /* swallow */ }
  };

  /* navigator.clipboard.writeText / write */
  const CP = window.Clipboard?.prototype;
  if (CP?.writeText) {
    const _writeText = CP.writeText;
    CP.writeText = function (text) { report(String(text)); return _writeText.apply(this, arguments); };
  }
  if (CP?.write) {
    const _write = CP.write;
    CP.write = function (items) {
      try {
        for (const item of items || []) {
          if (item?.types?.includes("text/plain")) {
            item.getType("text/plain").then((b) => b.text()).then(report).catch(() => {});
          }
        }
      } catch { /* swallow */ }
      return _write.apply(this, arguments);
    };
  }

  /* e.clipboardData.setData(...) inside a copy handler */
  const DT = window.DataTransfer?.prototype;
  if (DT?.setData) {
    const _setData = DT.setData;
    DT.setData = function (format, data) {
      if (/^text(?:\/plain)?$/i.test(String(format))) report(String(data));
      return _setData.apply(this, arguments);
    };
  }

  /* document.execCommand("copy") on a selected (often hidden) textarea */
  const _exec = Document.prototype.execCommand;
  Document.prototype.execCommand = function (cmd) {
    try {
      if (String(cmd).toLowerCase() === "copy") {
        let text = String(window.getSelection?.() || "");
        if (!text) {
          for (const el of document.querySelectorAll("textarea, input")) {
            if (el.selectionEnd > el.selectionStart) { text = el.value.slice(el.selectionStart, el.selectionEnd); break; }
          }
        }
        report(text);
      }
    } catch { /* swallow */ }
    return _exec.apply(this, arguments);
  };
})();
