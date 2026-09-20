/**
 * Simple static file server for test HTML pages.
 * Serves test pages on http://localhost:8080/
 */
import { createServer } from "http";
import { readFileSync, existsSync } from "fs";
import { resolve, dirname, extname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 8080;

const MIME = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json"
};

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  let filePath = url.pathname === "/" ? "/index.html" : url.pathname;
  filePath = resolve(__dirname, "." + filePath);

  if (!existsSync(filePath)) {
    // Generate index listing
    if (url.pathname === "/" || url.pathname === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<!DOCTYPE html>
<html><head><title>PhishClean Test Pages</title>
<style>
  body { font-family: sans-serif; max-width: 700px; margin: 40px auto; background: #0f1117; color: #e2e8f0; }
  h1 { color: #22c55e; }
  a { color: #60a5fa; display: block; margin: 12px 0; font-size: 18px; }
  .desc { color: #94a3b8; font-size: 14px; margin-left: 20px; }
</style></head>
<body>
  <h1>PhishClean Test Pages</h1>
  <p>Click each page to test extension detection.</p>
  <a href="/test-password.html">1. Password Field Detection</a>
  <div class="desc">Expected: PASSWORD_FIELD (+20), level: safe, NO alert</div>
  <a href="/test-form-mismatch.html">2. Domain Mismatch Detection</a>
  <div class="desc">Expected: PASSWORD_FIELD (+20) + DOMAIN_MISMATCH (+30) = 50, warning, NO alert</div>
  <a href="/test-phishing-combo.html?token=abc123session">3. Phishing Combo (with token param)</a>
  <div class="desc">Expected (Pro): PASSWORD_FIELD + DOMAIN_MISMATCH + QUERY_TOKEN = 70, danger, ALERT!</div>
  <a href="/test-hidden-iframe.html">4. Hidden Iframe Detection</a>
  <div class="desc">Expected (Pro): HIDDEN_IFRAME (+25), safe, no alert</div>
  <a href="/test-jwt-url.html?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U">5. JWT in URL Detection</a>
  <div class="desc">Expected (Pro): JWT_URL (+35), warning, no alert alone</div>
  <a href="/test-auth-leak.html">6. Auth Header Leak Detection</a>
  <div class="desc">Expected (Pro): Click button to trigger AUTH_HEADER_THIRD_PARTY (+30)</div>
  <a href="/test-safe-login.html">7. Safe Login (Control — NO alert)</a>
  <div class="desc">Expected: PASSWORD_FIELD only (+20), safe, NO alert</div>
</body></html>`);
      return;
    }
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  const ext = extname(filePath);
  res.writeHead(200, { "Content-Type": MIME[ext] || "text/plain" });
  res.end(readFileSync(filePath));
});

server.listen(PORT, () => {
  console.log(`\nTest pages server running on http://localhost:${PORT}`);
  console.log("Open in Chrome with the PhishClean extension loaded.\n");
});
