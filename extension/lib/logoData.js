/* PhishClean logo — drawn with jsPDF vector primitives.
   Call drawPhishCleanLogo(doc, x, y, size) to render the shield + checkmark. */

function drawPhishCleanLogo(doc, x, y, size) {
  var s = size / 36; // scale factor (logo viewBox is 32x36)

  // Shield outer — dark
  doc.setFillColor(17, 17, 17);
  doc.triangle(
    x + 16 * s, y + 1.5 * s,
    x + 3 * s,  y + 7 * s,
    x + 3 * s,  y + 17.5 * s,
    "F"
  );
  // Since jsPDF doesn't have complex paths easily, we'll draw with lines
  // Use a simpler rectangle + triangle approach

  // Actually let's just use a filled polygon approach via doc.lines()
  // Reset and draw the full shield with doc.lines

  // Shield outer path: M16,1.5 L3,7 L3,17.5 C3,26.5 8.5,34 16,36 C23.5,34 29,26.5 29,17.5 L29,7 Z
  // We approximate the curve with straight segments

  var ox = x;
  var oy = y;

  doc.setFillColor(17, 17, 17);
  var outerPts = [
    [16, 1.5], [29, 7], [29, 12], [29, 17.5],
    [29, 21], [27.5, 25], [25, 28.5], [22, 31.5],
    [19.5, 33.5], [16, 36],
    [12.5, 33.5], [10, 31.5], [7, 28.5],
    [4.5, 25], [3, 21], [3, 17.5], [3, 12], [3, 7]
  ];

  var startX = ox + outerPts[0][0] * s;
  var startY = oy + outerPts[0][1] * s;
  var lines = [];
  for (var i = 1; i < outerPts.length; i++) {
    lines.push([
      outerPts[i][0] * s - outerPts[i - 1][0] * s,
      outerPts[i][1] * s - outerPts[i - 1][1] * s
    ]);
  }
  doc.lines(lines, startX, startY, [1, 1], "F", true);

  // Shield inner — slightly lighter
  doc.setFillColor(26, 26, 26);
  var innerPts = [
    [16, 4.5], [26, 9], [26, 13], [26, 17.5],
    [26, 20.5], [24.5, 24], [22.5, 27], [20, 29.5],
    [18, 31.5], [16, 33],
    [14, 31.5], [12, 29.5], [9.5, 27],
    [7.5, 24], [6, 20.5], [6, 17.5], [6, 13], [6, 9]
  ];
  startX = ox + innerPts[0][0] * s;
  startY = oy + innerPts[0][1] * s;
  lines = [];
  for (var j = 1; j < innerPts.length; j++) {
    lines.push([
      innerPts[j][0] * s - innerPts[j - 1][0] * s,
      innerPts[j][1] * s - innerPts[j - 1][1] * s
    ]);
  }
  doc.lines(lines, startX, startY, [1, 1], "F", true);

  // Green checkmark
  doc.setDrawColor(34, 197, 94);
  doc.setLineWidth(2.8 * s);
  doc.setLineCap("round");
  doc.setLineJoin("round");

  // Checkmark: M11,18.5 L14.5,22 L21.5,15
  var cx1 = ox + 11 * s;
  var cy1 = oy + 18.5 * s;
  var cx2 = ox + 14.5 * s;
  var cy2 = oy + 22 * s;
  var cx3 = ox + 21.5 * s;
  var cy3 = oy + 15 * s;

  doc.line(cx1, cy1, cx2, cy2);
  doc.line(cx2, cy2, cx3, cy3);

  // Reset line settings
  doc.setLineWidth(0.2);
  doc.setDrawColor(0);
  doc.setLineCap("butt");
  doc.setLineJoin("miter");
}
