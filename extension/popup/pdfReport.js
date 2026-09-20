/* PhishClean PDF Report Generator
   Depends on: jspdf.umd.min.js (loaded via <script>), logoData.js (drawPhishCleanLogo)
*/

function generatePhishCleanReport(data) {
  var userName = data.userName;
  var installId = data.installId || "";
  var stats = data.stats || { blocked: 0 };
  var threats = data.threats || [];
  var trustedDomains = data.trustedDomains || [];
  var license = data.license || {};
  var generatedAt = data.generatedAt || new Date().toISOString();

  var doc = new jspdf.jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  var pageW = 210;
  var margin = 18;
  var contentW = pageW - margin * 2;
  var y = 0;
  var siteUrl = "https://www.phishclean.com";

  /* Start a fresh page: accent bars + reset cursor. Footers are stamped on
     every page in one pass at the end, so page breaks never touch font state. */
  function newPage() {
    doc.addPage();
    doc.setFillColor(17, 17, 17);
    doc.rect(0, 0, pageW, 3, "F");
    doc.setFillColor(34, 197, 94);
    doc.rect(0, 3, pageW, 1.2, "F");
    y = 16;
  }

  /* ── Top accent bar ── */
  doc.setFillColor(17, 17, 17);
  doc.rect(0, 0, pageW, 3, "F");
  doc.setFillColor(34, 197, 94);
  doc.rect(0, 3, pageW, 1.2, "F");

  y = 16;

  /* ── Header: Logo + Brand on one line (landing page nav style) ── */
  /* Logo height = cap-height of "P" at 16pt bold (~4.5mm) */
  var hLogoH = 4.8;
  var hLogoW = hLogoH * (32 / 36);
  doc.setFontSize(16);
  doc.setFont(undefined, "bold");
  var hBrandW = doc.getTextWidth("PhishClean");

  /* Text baseline at y+2; align logo top with cap-height top */
  var hTextY = y + 2;
  var hLogoY = hTextY - hLogoH;
  drawPhishCleanLogo(doc, margin, hLogoY, hLogoH);

  var hx = margin + hLogoW + 1.5;
  doc.setFontSize(16);
  doc.setFont(undefined, "bold");
  doc.setTextColor(17, 17, 17);
  doc.text("PhishClean", hx, hTextY);

  doc.setFontSize(9);
  doc.setFont(undefined, "normal");
  doc.setTextColor(170, 170, 170);
  doc.text("Security Report", hx, hTextY + 5);

  /* Make header area clickable -> landing page */
  doc.link(margin, y - 4, hLogoW + 1.5 + hBrandW + 4, 10, { url: siteUrl });

  /* Date - right-aligned */
  var dateStr = new Date(generatedAt).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric"
  });
  doc.setFontSize(9);
  doc.setTextColor(150, 150, 150);
  doc.text(dateStr, pageW - margin, y + 1, { align: "right" });

  y += 18;

  /* ── Divider ── */
  doc.setDrawColor(230, 230, 230);
  doc.setLineWidth(0.4);
  doc.line(margin, y, pageW - margin, y);
  y += 10;

  /* ── User info bar ── */
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, y - 4, contentW, 18, 3, 3, "F");
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.roundedRect(margin, y - 4, contentW, 18, 3, 3, "S");

  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text("PREPARED FOR", margin + 6, y + 1);
  doc.setFontSize(12);
  doc.setFont(undefined, "bold");
  doc.setTextColor(30, 41, 59);
  doc.text(userName, margin + 6, y + 7);

  /* Plan badge */
  var planText = license.is_paid
    ? (license.plan_type === "annual" ? "Pro (Annual)" : "Pro (Monthly)")
    : "Free";
  var badgeX = pageW - margin - 40;
  doc.setFontSize(9);
  doc.setFont(undefined, "normal");
  doc.setTextColor(100, 116, 139);
  doc.text("PLAN", badgeX, y + 1);
  if (license.is_paid) {
    doc.setFillColor(34, 197, 94);
    doc.roundedRect(badgeX, y + 3, 30, 6, 2, 2, "F");
    doc.setFontSize(8);
    doc.setFont(undefined, "bold");
    doc.setTextColor(255, 255, 255);
    doc.text(planText, badgeX + 15, y + 7.2, { align: "center" });
  } else {
    doc.setFontSize(10);
    doc.setFont(undefined, "normal");
    doc.setTextColor(100, 116, 139);
    doc.text(planText, badgeX, y + 7);
  }

  doc.setFont(undefined, "normal");
  y += 22;

  /* ── Summary Stats Cards ── */
  var cardW = (contentW - 6) / 3;
  var cardH = 22;
  var cards = [
    { label: "Threats Blocked", value: String(stats.blocked), color: [239, 68, 68] },
    { label: "Detailed Records", value: String(threats.length), color: [59, 130, 246] },
    { label: "Trusted Domains", value: String(trustedDomains.length), color: [34, 197, 94] }
  ];

  for (var c = 0; c < cards.length; c++) {
    var cx = margin + c * (cardW + 3);

    doc.setDrawColor(230, 230, 230);
    doc.setLineWidth(0.3);
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(cx, y, cardW, cardH, 2, 2, "FD");

    /* Colored top edge */
    doc.setFillColor(cards[c].color[0], cards[c].color[1], cards[c].color[2]);
    doc.rect(cx + 1, y + 0.5, cardW - 2, 1.5, "F");

    doc.setFontSize(18);
    doc.setFont(undefined, "bold");
    doc.setTextColor(cards[c].color[0], cards[c].color[1], cards[c].color[2]);
    doc.text(cards[c].value, cx + cardW / 2, y + 11, { align: "center" });

    doc.setFontSize(7.5);
    doc.setFont(undefined, "normal");
    doc.setTextColor(120, 120, 120);
    doc.text(cards[c].label, cx + cardW / 2, y + 17, { align: "center" });
  }

  y += cardH + 12;

  /* ── Threat Details Table ── */
  doc.setFontSize(13);
  doc.setFont(undefined, "bold");
  doc.setTextColor(17, 17, 17);
  doc.text("Threat Details", margin, y);
  y += 8;

  if (threats.length > 0) {
    var colX = [margin + 1, margin + 26, margin + 82, margin + 100];
    var colLabels = ["Date", "Domain", "Score", "Reasons"];
    /* Width available for the wrapped Reasons column */
    var reasonsW = pageW - margin - colX[3] - 2;
    /* Line height for 8.5pt text (8.5pt * 1.15 line-height in mm) */
    var rowLineH = 3.45;

    /* Table header — repeated at the top of every continuation page */
    function drawThreatHeader() {
      doc.setFillColor(30, 41, 59);
      doc.roundedRect(margin, y - 4.5, contentW, 7.5, 1.5, 1.5, "F");
      doc.setFontSize(8.5);
      doc.setFont(undefined, "bold");
      doc.setTextColor(255, 255, 255);
      for (var h = 0; h < colLabels.length; h++) {
        doc.text(colLabels[h], colX[h], y);
      }
      y += 7;
      /* Restore row font state */
      doc.setFont(undefined, "normal");
      doc.setFontSize(8.5);
    }

    drawThreatHeader();

    for (var i = 0; i < threats.length; i++) {
      var t = threats[i];
      var d = new Date(t.occurred_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "2-digit" });
      var dom = t.domain || "";
      if (dom.length > 30) dom = dom.substring(0, 27) + "...";

      /* Full reasons, wrapped onto as many lines as needed — never truncated */
      var rsnLines = doc.splitTextToSize((t.reasons || []).join("; ") || "-", reasonsW);
      var rowH = 6.5 + (rsnLines.length - 1) * rowLineH;

      /* Break before the row if it wouldn't fit on this page */
      if (y + rowH > 272) {
        newPage();
        drawThreatHeader();
      }

      /* Alternate row background (sized to the full wrapped row) */
      if (i % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y - 3.5, contentW, rowH, "F");
      }

      /* Row bottom border */
      doc.setDrawColor(240, 240, 240);
      doc.setLineWidth(0.2);
      doc.line(margin, y - 3.5 + rowH, pageW - margin, y - 3.5 + rowH);

      /* Score color */
      var scoreColor = t.score >= 50 ? [220, 38, 38] : t.score >= 25 ? [217, 119, 6] : [22, 163, 74];

      doc.setTextColor(71, 85, 105);
      doc.text(d, colX[0], y);
      doc.text(dom, colX[1], y);

      doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
      doc.setFont(undefined, "bold");
      doc.text(String(t.score), colX[2], y);

      doc.setTextColor(71, 85, 105);
      doc.setFont(undefined, "normal");
      doc.text(rsnLines, colX[3], y);

      y += rowH;
    }
    y += 8;
  } else {
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(margin, y - 3, contentW, 14, 2, 2, "F");
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text("No threats detected yet. Threats will appear here as they are blocked.", margin + 6, y + 4);
    y += 18;
  }

  /* ── Trusted Domains ── */
  if (y > 240) {
    newPage();
  }

  doc.setFontSize(13);
  doc.setFont(undefined, "bold");
  doc.setTextColor(17, 17, 17);
  doc.text("Trusted Domains", margin, y);
  y += 8;

  if (trustedDomains.length > 0) {
    doc.setFontSize(9);
    doc.setFont(undefined, "normal");

    var colWidth = contentW / 2;
    var leftX = margin + 4;
    var rightX = margin + colWidth + 4;
    var startY = y;
    var midpoint = Math.ceil(trustedDomains.length / 2);

    for (var k = 0; k < trustedDomains.length; k++) {
      if (y > 270) {
        newPage();
        startY = y;
        /* Restore list font state after the page break */
        doc.setFontSize(9);
        doc.setFont(undefined, "normal");
      }

      var dx = k < midpoint ? leftX : rightX;
      var dy = k < midpoint ? startY + k * 6 : startY + (k - midpoint) * 6;

      /* Green bullet */
      doc.setFillColor(34, 197, 94);
      doc.circle(dx, dy - 1, 1, "F");

      doc.setTextColor(51, 65, 85);
      doc.text(trustedDomains[k], dx + 4, dy);
    }

    y = startY + (midpoint * 6) + 6;
  } else {
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(margin, y - 3, contentW, 12, 2, 2, "F");
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text("No trusted domains configured.", margin + 6, y + 3);
    y += 16;
  }

  /* ── Install ID (small, at bottom) ── */
  if (installId) {
    if (y > 265) {
      newPage();
    }
    y += 4;
    doc.setFontSize(7);
    doc.setTextColor(180, 180, 180);
    doc.text("Install ID: " + installId, margin, y);
  }

  /* ── Add footer to all pages ── */
  var totalPages = doc.internal.getNumberOfPages();
  for (var p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    addFooter(doc, pageW, margin, p, totalPages);
  }

  /* ── Save ── */
  var dateSlug = new Date().toISOString().split("T")[0];
  doc.save("PhishClean-Report-" + dateSlug + ".pdf");
}

/* ── Footer helper ── */
function addFooter(doc, pageW, margin, pageNum, totalPages) {
  var footerY = 280;
  var siteUrl = "https://www.phishclean.com";
  var centerX = pageW / 2;

  /* Divider line */
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.3);
  doc.line(margin, footerY, pageW - margin, footerY);

  /* Row 1: Logo + brand name on one line (centered, clickable) */
  /* Logo height = cap-height of "P" at 8pt bold (~2.3mm) */
  var fLogoH = 2.5;
  var fLogoW = fLogoH * (32 / 36);
  doc.setFontSize(8);
  doc.setFont(undefined, "bold");
  var fBrandW = doc.getTextWidth("PhishClean");
  var fGap = 1;
  var fRowW = fLogoW + fGap + fBrandW;
  var fStartX = centerX - fRowW / 2;

  /* Align logo top with cap-height top */
  var fTextY = footerY + 4.8;
  var fLogoY = fTextY - fLogoH;
  drawPhishCleanLogo(doc, fStartX, fLogoY, fLogoH);
  doc.setTextColor(50, 50, 50);
  doc.text("PhishClean", fStartX + fLogoW + fGap, fTextY);
  doc.link(fStartX, footerY + 1, fRowW + 2, 6, { url: siteUrl });

  /* Row 2: Links (centered) */
  doc.setFontSize(6.5);
  doc.setFont(undefined, "normal");
  var sep = "   \u00B7   ";
  var links = [
    { text: "phishclean.com", url: siteUrl },
    { text: "support@phishclean.com", url: "mailto:support@phishclean.com" },
    { text: "Privacy Policy", url: siteUrl + "/privacy" },
    { text: "Terms of Service", url: siteUrl + "/terms" }
  ];

  /* Measure total width to center the row */
  doc.setTextColor(100, 100, 100);
  var sepW = doc.getTextWidth(sep);
  var totalW = 0;
  for (var i = 0; i < links.length; i++) {
    totalW += doc.getTextWidth(links[i].text);
    if (i < links.length - 1) totalW += sepW;
  }

  var lx = centerX - totalW / 2;
  var ly = footerY + 9;
  for (var j = 0; j < links.length; j++) {
    var w = doc.getTextWidth(links[j].text);
    doc.setTextColor(59, 130, 246);
    doc.textWithLink(links[j].text, lx, ly, { url: links[j].url });
    lx += w;
    if (j < links.length - 1) {
      doc.setTextColor(190, 190, 190);
      doc.text(sep, lx, ly);
      lx += sepW;
    }
  }

  /* Row 3: Privacy note + page number */
  doc.setTextColor(190, 190, 190);
  doc.setFontSize(6);
  doc.text("All detection runs locally on your device. No browsing data is sent to any server.", centerX, footerY + 13, { align: "center" });

  if (pageNum && totalPages) {
    doc.setTextColor(160, 160, 160);
    doc.text("Page " + pageNum + " of " + totalPages, pageW - margin, footerY + 13, { align: "right" });
  }
}
