import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// ─── Light-theme colour palette ──────────────────────────────────────────────
const C = {
  // Page & structure
  white:       [255, 255, 255],
  pageBg:      [248, 250, 252],   // slate-50
  cardBg:      [255, 255, 255],
  sectionBg:   [241, 245, 249],   // slate-100

  // Text
  textDark:    [15,  23,  42],    // slate-900
  textBody:    [30,  41,  59],    // slate-800
  textSub:     [71,  85, 105],    // slate-600
  textMuted:   [100, 116, 139],   // slate-500
  textXMuted:  [148, 163, 184],   // slate-400

  // Borders
  border:      [226, 232, 240],   // slate-200
  borderMd:    [203, 213, 225],   // slate-300

  // Brand accent – sky blue
  accent:      [14, 165, 233],    // sky-500
  accentDk:    [2,  132, 199],    // sky-600
  accentLt:    [224, 242, 254],   // sky-100
  accentText:  [7,  89, 133],     // sky-800

  // Status colours (vivid but not neon)
  critical:    [220,  38,  38],   // red-600
  criticalLt:  [254, 226, 226],   // red-100
  high:        [234, 88,  12],    // orange-600
  highLt:      [255, 237, 213],   // orange-100
  medium:      [202, 138,   4],   // yellow-600
  mediumLt:    [254, 249, 195],   // yellow-100
  low:         [22, 163,  74],    // green-600
  lowLt:       [220, 252, 231],   // green-100
  purple:      [124,  58, 237],   // violet-600
  purpleLt:    [237, 233, 254],   // violet-100
  rose:        [225,  29,  72],   // rose-600
  roseLt:      [255, 228, 230],   // rose-100
};

// ─── Severity mappings ────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: C.criticalLt, text: C.critical, badge: C.critical },
  HIGH:     { bg: C.highLt,     text: C.high,     badge: C.high     },
  MEDIUM:   { bg: C.mediumLt,   text: C.medium,   badge: C.medium   },
  LOW:      { bg: C.lowLt,      text: C.low,      badge: C.low      },
};

const THREAT_COLOR = {
  Critical:    C.critical,
  Malicious:   C.rose,
  'High Risk': C.high,
  Suspicious:  C.medium,
  Contextual:  C.accentDk,
};

const THREAT_BG = {
  Critical:    C.criticalLt,
  Malicious:   C.roseLt,
  'High Risk': C.highLt,
  Suspicious:  C.mediumLt,
  Contextual:  C.accentLt,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Fill a rounded rectangle */
function rRect(doc, x, y, w, h, r, fill, stroke) {
  doc.setFillColor(...fill);
  if (stroke) {
    doc.setDrawColor(...stroke);
    doc.setLineWidth(0.3);
    doc.roundedRect(x, y, w, h, r, r, 'FD');
  } else {
    doc.roundedRect(x, y, w, h, r, r, 'F');
  }
}

/** Draw every-page header band */
function drawPageHeader(doc, pageW, pageNum, totalPages) {
  // Top colour bar
  doc.setFillColor(...C.accentDk);
  doc.rect(0, 0, pageW, 7, 'F');

  // Brand name in bar
  doc.setTextColor(...C.white);
  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'bold');
  doc.text('SecuRAG', 14, 5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(200, 230, 255);
  doc.text('AI-Powered SOC Investigation Platform', 38, 5);

  // Page number (right)
  doc.setTextColor(...C.white);
  doc.setFontSize(7);
  doc.text(`Page ${pageNum}`, pageW - 14, 5, { align: 'right' });
}

/** Draw every-page footer */
function drawPageFooter(doc, pageW, pageH, reportTitle) {
  doc.setFillColor(...C.sectionBg);
  doc.rect(0, pageH - 10, pageW, 10, 'F');
  doc.setDrawColor(...C.border);
  doc.setLineWidth(0.3);
  doc.line(0, pageH - 10, pageW, pageH - 10);

  doc.setTextColor(...C.textMuted);
  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'normal');
  doc.text('CONFIDENTIAL — For authorised SOC personnel only', 14, pageH - 3.5);
  const ts = new Date().toLocaleString();
  doc.text(`Generated: ${ts}`, pageW - 14, pageH - 3.5, { align: 'right' });
}

/** Section heading with left accent bar */
function sectionHeading(doc, text, y, pageW) {
  // Left accent bar
  doc.setFillColor(...C.accent);
  doc.rect(14, y, 3, 7, 'F');

  // Background strip
  rRect(doc, 18, y, pageW - 32, 7, 1, C.accentLt);

  // Text
  doc.setTextColor(...C.accentText);
  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'bold');
  doc.text(text.toUpperCase(), 22, y + 5);
  return y + 13;
}

/** Stat card */
function statCard(doc, label, value, unit, x, y, w, accentColor, lightBg) {
  rRect(doc, x, y, w, 22, 3, lightBg, C.borderMd);

  // Value
  doc.setTextColor(...accentColor);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text(String(value), x + w / 2, y + 11, { align: 'center' });

  // Label
  doc.setTextColor(...C.textSub);
  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'normal');
  doc.text(label.toUpperCase(), x + w / 2, y + 17, { align: 'center' });
}

/** Risk score ring (simple arc substitute using filled/partial circles) */
function riskBlock(doc, score, x, y, size) {
  const riskCol =
    score >= 80 ? C.critical :
    score >= 60 ? C.high     :
    score >= 40 ? C.medium   :
                  C.low;
  const riskLt =
    score >= 80 ? C.criticalLt :
    score >= 60 ? C.highLt     :
    score >= 40 ? C.mediumLt   :
                  C.lowLt;

  rRect(doc, x, y, size, size, 4, riskLt, C.borderMd);

  // Score number
  doc.setTextColor(...riskCol);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text(String(score), x + size / 2, y + size / 2 + 3, { align: 'center' });

  // Label
  doc.setTextColor(...C.textMuted);
  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'normal');
  doc.text('RISK SCORE', x + size / 2, y + size - 5, { align: 'center' });
}

/** Add a new blank page with standard header/footer */
function addPage(doc, pageW, pageH, reportTitle) {
  doc.addPage();
  // White background
  doc.setFillColor(...C.white);
  doc.rect(0, 0, pageW, pageH, 'F');
  const pgNum = doc.internal.getCurrentPageInfo().pageNumber;
  drawPageHeader(doc, pageW, pgNum, '?');
  drawPageFooter(doc, pageW, pageH, reportTitle);
  return 16; // content start Y after header band
}

// ─── MAIN EXPORT ─────────────────────────────────────────────────────────────
export async function generateInvestigationPDF(investigation) {
  const doc   = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();   // 210 mm
  const pageH = doc.internal.pageSize.getHeight();  // 297 mm

  const inv      = investigation;
  const now      = new Date();
  const iocs     = inv.iocs_detected      || [];
  const mitres   = inv.mitre_techniques   || [];
  const actions  = inv.recommended_actions|| {};
  const severity = (inv.severity || 'MEDIUM').toUpperCase();
  const sevStyle = SEV[severity] || SEV.MEDIUM;

  const reportTitle = inv.title || 'Security Investigation Report';

  // ══════════════════════════════════════════════════════════════════════════
  // PAGE 1 — COVER
  // ══════════════════════════════════════════════════════════════════════════
  // White base
  doc.setFillColor(...C.white);
  doc.rect(0, 0, pageW, pageH, 'F');

  // ── Top header band ───────────────────────────────────────────────────────
  doc.setFillColor(...C.accentDk);
  doc.rect(0, 0, pageW, 22, 'F');

  doc.setTextColor(...C.white);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('SecuRAG', 14, 13);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(200, 230, 255);
  doc.text('AI-Powered Cyber Threat Investigation Platform', 14, 19);

  // TLP badge (top-right)
  const tlpText  = severity === 'CRITICAL' || severity === 'HIGH' ? 'TLP:RED — CONFIDENTIAL' : 'TLP:AMBER — SENSITIVE';
  const tlpColor = severity === 'CRITICAL' || severity === 'HIGH' ? C.critical : C.high;
  rRect(doc, pageW - 72, 5, 58, 12, 2, C.white);
  doc.setTextColor(...tlpColor);
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'bold');
  doc.text(tlpText, pageW - 43, 12.5, { align: 'center' });

  // ── Hero section ──────────────────────────────────────────────────────────
  const heroY = 34;

  // Severity pill
  rRect(doc, 14, heroY, 42, 9, 2, sevStyle.bg);
  doc.setTextColor(...sevStyle.text);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text(`▲ ${severity} SEVERITY`, 35, heroY + 6.2, { align: 'center' });

  // Attack stage pill
  if (inv.attack_stage) {
    rRect(doc, 60, heroY, 70, 9, 2, C.sectionBg, C.borderMd);
    doc.setTextColor(...C.textSub);
    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'normal');
    doc.text(inv.attack_stage.slice(0, 36), 95, heroY + 6.2, { align: 'center' });
  }

  // Investigation title
  doc.setTextColor(...C.textDark);
  doc.setFontSize(17);
  doc.setFont('helvetica', 'bold');
  const titleLines = doc.splitTextToSize(reportTitle, pageW - 28);
  doc.text(titleLines.slice(0, 3), 14, heroY + 20);

  // Divider
  doc.setDrawColor(...C.borderMd);
  doc.setLineWidth(0.4);
  doc.line(14, heroY + 30, pageW - 14, heroY + 30);

  // Meta row
  const metaY = heroY + 37;
  const metaItems = [
    { label: 'Alert Source', value: inv.alert_type || 'Unknown' },
    { label: 'AI Engine',    value: inv.model_used || 'SecuRAG AI' },
    { label: 'Report Date',  value: now.toLocaleDateString() },
    { label: 'Report Time',  value: now.toLocaleTimeString() },
  ];
  metaItems.forEach((m, i) => {
    const mx = 14 + i * 49;
    doc.setTextColor(...C.textMuted);
    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'normal');
    doc.text(m.label.toUpperCase(), mx, metaY);
    doc.setTextColor(...C.textBody);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(m.value.slice(0, 20), mx, metaY + 5.5);
  });

  // ── Stat cards row ────────────────────────────────────────────────────────
  const statY = metaY + 16;
  const totalMalicious = iocs.filter(i => ['Malicious','Critical','High Risk'].includes(i.threat_level)).length;
  const uniqueTactics  = [...new Set(mitres.map(t => t.tactic).filter(Boolean))].length;
  const cardW = 40;
  const gap   = 3.5;

  // Risk score block
  riskBlock(doc, inv.risk_score || 0, 14, statY, cardW);

  // Other stat cards
  [
    { label: 'Total IOCs',      value: iocs.length,     color: C.accentDk,  bg: C.accentLt  },
    { label: 'Malicious/Crit',  value: totalMalicious,  color: C.critical,  bg: C.criticalLt},
    { label: 'MITRE Techniques',value: mitres.length,   color: C.purple,    bg: C.purpleLt  },
    { label: 'ATT&CK Tactics',  value: uniqueTactics,   color: C.high,      bg: C.highLt    },
  ].forEach((s, i) => {
    const cx = 14 + cardW + gap + i * (cardW + gap);
    statCard(doc, s.label, s.value, '', cx, statY, cardW, s.color, s.bg);
  });

  // ── Executive Summary ─────────────────────────────────────────────────────
  const sumY = statY + 28;
  rRect(doc, 14, sumY, pageW - 28, 70, 3, C.sectionBg, C.border);

  // Left accent stripe inside card
  doc.setFillColor(...C.accent);
  doc.roundedRect(14, sumY, 3, 70, 1.5, 1.5, 'F');

  doc.setTextColor(...C.accentText);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('EXECUTIVE THREAT SUMMARY', 22, sumY + 7);

  doc.setTextColor(...C.textBody);
  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'normal');
  const summaryLines = doc.splitTextToSize(inv.summary || 'No summary available.', pageW - 50);
  doc.text(summaryLines.slice(0, 9), 22, sumY + 14);

  // ── IOC quick breakdown boxes ─────────────────────────────────────────────
  const ioqY = sumY + 76;
  const typeCount = {};
  iocs.forEach(ioc => { typeCount[ioc.type || 'Other'] = (typeCount[ioc.type || 'Other'] || 0) + 1; });
  const typeEntries = Object.entries(typeCount).slice(0, 5);

  if (typeEntries.length > 0) {
    doc.setTextColor(...C.textMuted);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    doc.text('IOC TYPE BREAKDOWN', 14, ioqY);

    const bW = (pageW - 28) / typeEntries.length;
    typeEntries.forEach(([type, cnt], i) => {
      const bx = 14 + i * bW;
      rRect(doc, bx + 1, ioqY + 4, bW - 2, 14, 2, C.accentLt, C.border);
      doc.setTextColor(...C.accentDk);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(String(cnt), bx + bW / 2, ioqY + 13, { align: 'center' });
      doc.setTextColor(...C.textSub);
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'normal');
      doc.text(type, bx + bW / 2, ioqY + 16.5, { align: 'center' });
    });
  }

  // ── Cover footer ──────────────────────────────────────────────────────────
  drawPageFooter(doc, pageW, pageH, reportTitle);

  // ══════════════════════════════════════════════════════════════════════════
  // PAGE 2 — IOC INTELLIGENCE TABLE
  // ══════════════════════════════════════════════════════════════════════════
  if (iocs.length > 0) {
    let curY = addPage(doc, pageW, pageH, reportTitle);
    curY = sectionHeading(doc, '02 — Extracted IOC Intelligence', curY, pageW);

    // Summary ribbon
    rRect(doc, 14, curY, pageW - 28, 10, 2, C.accentLt, C.border);
    doc.setTextColor(...C.accentText);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(
      `${iocs.length} indicators identified  ·  ${totalMalicious} classified Malicious or Critical  ·  ${iocs.length - totalMalicious} Suspicious / Contextual`,
      pageW / 2, curY + 6.5, { align: 'center' }
    );
    curY += 15;

    autoTable(doc, {
      startY: curY,
      head: [['#', 'Type', 'Indicator Value', 'Threat Level', 'Context / Notes']],
      body: iocs.map((ioc, i) => [
        i + 1,
        ioc.type || '-',
        ioc.value || '-',
        ioc.threat_level || 'Unknown',
        (ioc.context || '-').slice(0, 65),
      ]),
      theme: 'grid',
      styles: {
        font: 'helvetica',
        fontSize: 7.5,
        cellPadding: 2.8,
        textColor: C.textBody,
        lineColor: C.border,
        lineWidth: 0.25,
        overflow: 'ellipsize',
        fillColor: C.white,
      },
      headStyles: {
        fillColor: C.accentDk,
        textColor: C.white,
        fontStyle: 'bold',
        fontSize: 7.5,
      },
      columnStyles: {
        0: { cellWidth: 8,  halign: 'center', textColor: C.textMuted },
        1: { cellWidth: 22, font: 'courier',  textColor: C.accentDk, fontStyle: 'bold' },
        2: { cellWidth: 62, font: 'courier',  fontSize: 7 },
        3: { cellWidth: 30, halign: 'center' },
        4: { cellWidth: 62, fontSize: 7, textColor: C.textSub },
      },
      alternateRowStyles: { fillColor: C.pageBg },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 3) {
          const lvl = data.cell.raw;
          data.cell.styles.textColor  = THREAT_COLOR[lvl]  || C.textBody;
          data.cell.styles.fillColor  = THREAT_BG[lvl]     || C.white;
          data.cell.styles.fontStyle  = 'bold';
        }
      },
      didDrawPage: (d) => {
        const pg = doc.internal.getCurrentPageInfo().pageNumber;
        drawPageHeader(doc, pageW, pg, '?');
        drawPageFooter(doc, pageW, pageH, reportTitle);
      },
      margin: { left: 14, right: 14, top: 16, bottom: 14 },
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PAGE 3 — MITRE ATT&CK MAPPING
  // ══════════════════════════════════════════════════════════════════════════
  if (mitres.length > 0) {
    let mitreY = addPage(doc, pageW, pageH, reportTitle);
    mitreY = sectionHeading(doc, '03 — MITRE ATT&CK Matrix Correlation', mitreY, pageW);

    // Tactic chips row
    const tactics = [...new Set(mitres.map(t => t.tactic).filter(Boolean))];
    let chipX = 14;
    const chipY = mitreY;
    tactics.forEach(tac => {
      const tw = doc.getTextWidth(tac) + 8;
      rRect(doc, chipX, chipY, tw, 7, 2, C.purpleLt, C.border);
      doc.setTextColor(...C.purple);
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'bold');
      doc.text(tac, chipX + tw / 2, chipY + 5, { align: 'center' });
      chipX += tw + 3;
      if (chipX > pageW - 40) { chipX = 14; }
    });
    mitreY += 13;

    autoTable(doc, {
      startY: mitreY,
      head: [['Technique ID', 'Name', 'Tactic', 'Description', 'Detection Hint']],
      body: mitres.map(t => [
        t.id    || '-',
        t.name  || '-',
        t.tactic|| '-',
        (t.description || '-').slice(0, 90),
        (t.detection   || '-').slice(0, 70),
      ]),
      theme: 'grid',
      styles: {
        font: 'helvetica',
        fontSize: 7.5,
        cellPadding: 2.8,
        textColor: C.textBody,
        lineColor: C.border,
        lineWidth: 0.25,
        overflow: 'ellipsize',
        fillColor: C.white,
      },
      headStyles: {
        fillColor: [124, 58, 237],  // violet-600
        textColor: C.white,
        fontStyle: 'bold',
        fontSize: 7.5,
      },
      columnStyles: {
        0: { cellWidth: 25, font: 'courier', textColor: C.critical, fontStyle: 'bold' },
        1: { cellWidth: 40, fontStyle: 'bold' },
        2: { cellWidth: 28, textColor: C.purple, fontStyle: 'bold' },
        3: { cellWidth: 55, fontSize: 7, textColor: C.textSub },
        4: { cellWidth: 40, fontSize: 7, textColor: [7, 89, 133] },
      },
      alternateRowStyles: { fillColor: C.pageBg },
      didDrawPage: () => {
        const pg = doc.internal.getCurrentPageInfo().pageNumber;
        drawPageHeader(doc, pageW, pg, '?');
        drawPageFooter(doc, pageW, pageH, reportTitle);
      },
      margin: { left: 14, right: 14, top: 16, bottom: 14 },
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PAGE 4 — SOC RESPONSE PLAYBOOK
  // ══════════════════════════════════════════════════════════════════════════
  let socY = addPage(doc, pageW, pageH, reportTitle);
  socY = sectionHeading(doc, '04 — SOC Response Playbook & Containment', socY, pageW);

  const imm  = actions.immediate_containment    || [];
  const erad = actions.eradication_remediation  || [];

  const renderChecklist = (items, headerText, headerBg, headerText2, checkColor) => {
    if (items.length === 0) return;
    if (socY + 14 > pageH - 18) { socY = addPage(doc, pageW, pageH, reportTitle); }

    // Sub-section header
    rRect(doc, 14, socY, pageW - 28, 9, 2, headerBg, C.borderMd);
    doc.setTextColor(...headerText2);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(headerText, 20, socY + 6.2);
    socY += 13;

    items.forEach((action, i) => {
      if (socY + 11 > pageH - 18) {
        socY = addPage(doc, pageW, pageH, reportTitle);
      }
      const rowH = 10;
      // Row background
      rRect(doc, 14, socY, pageW - 28, rowH, 1.5, i % 2 === 0 ? C.white : C.pageBg, C.border);

      // Number badge
      rRect(doc, 17, socY + 2, 6, 6, 1, checkColor);
      doc.setTextColor(...C.white);
      doc.setFontSize(6.5);
      doc.setFont('helvetica', 'bold');
      doc.text(String(i + 1), 20, socY + 6.5, { align: 'center' });

      // Checkbox outline
      doc.setDrawColor(...checkColor);
      doc.setLineWidth(0.5);
      doc.rect(26, socY + 2.5, 5, 5, 'S');

      // Action text
      doc.setTextColor(...C.textBody);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      const lines = doc.splitTextToSize(action, pageW - 60);
      doc.text(lines[0], 34, socY + 7);
      socY += rowH + 1.5;
    });
    socY += 5;
  };

  renderChecklist(imm,  'IMMEDIATE CONTAINMENT — TIER 1 / TIER 2',   C.criticalLt, C.critical, C.critical);
  renderChecklist(erad, 'ERADICATION & LONG-TERM HARDENING',          C.accentLt,   C.accentDk, C.accentDk);

  // ── Hunting Queries ───────────────────────────────────────────────────────
  const hq           = actions.hunting_queries || {};
  const queryEntries = Object.entries(hq).filter(([, v]) => v);

  if (queryEntries.length > 0) {
    if (socY + 20 > pageH - 18) { socY = addPage(doc, pageW, pageH, reportTitle); }
    socY = sectionHeading(doc, '05 — Threat Hunting & SIEM Queries', socY, pageW);

    const LANG_COLOR = { kql: C.accentDk, splunk: [214, 89, 0], sigma: C.purple };

    queryEntries.forEach(([lang, query]) => {
      if (socY + 36 > pageH - 18) { socY = addPage(doc, pageW, pageH, reportTitle); }

      const lc = LANG_COLOR[lang] || C.textSub;
      // Lang header
      rRect(doc, 14, socY, pageW - 28, 8, 2, C.sectionBg, C.borderMd);
      doc.setTextColor(...lc);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text(`● ${lang.toUpperCase()} QUERY`, 20, socY + 5.5);
      socY += 10;

      // Code block
      rRect(doc, 14, socY, pageW - 28, 28, 2, [248, 250, 252], C.borderMd);

      // Green dot decoration
      doc.setFillColor(52, 211, 153);
      doc.circle(19, socY + 4, 1.5, 'F');
      doc.setFillColor(251, 191, 36);
      doc.circle(23, socY + 4, 1.5, 'F');
      doc.setFillColor(244, 63, 94);
      doc.circle(27, socY + 4, 1.5, 'F');

      doc.setTextColor(22, 101, 52);   // green-800 for code
      doc.setFontSize(7);
      doc.setFont('courier', 'normal');
      const qlines = doc.splitTextToSize(query, pageW - 44);
      doc.text(qlines.slice(0, 5), 18, socY + 10);
      socY += 32;
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PAGE 5 — FULL FORENSIC REPORT (Markdown)
  // ══════════════════════════════════════════════════════════════════════════
  if (inv.full_report_markdown) {
    let mdY = addPage(doc, pageW, pageH, reportTitle);
    mdY = sectionHeading(doc, '06 — Full Forensic Investigation Report', mdY, pageW);

    const mdLines = doc.splitTextToSize(inv.full_report_markdown, pageW - 32);
    let li = 0;

    while (li < mdLines.length) {
      if (mdY > pageH - 18) {
        mdY = addPage(doc, pageW, pageH, reportTitle);
      }

      const line = mdLines[li];

      if (line.startsWith('# ') || line.startsWith('## ') || line.startsWith('### ')) {
        // Header line
        const cleanLine = line.replace(/^#+\s/, '');
        const lvl = (line.match(/^(#+)/) || ['','#'])[1].length;

        if (mdY + 12 > pageH - 18) { mdY = addPage(doc, pageW, pageH, reportTitle); }
        if (lvl === 1) {
          doc.setFillColor(...C.accentDk);
          doc.rect(14, mdY, 3, 7, 'F');
          rRect(doc, 18, mdY, pageW - 32, 7, 1, C.accentLt);
          doc.setTextColor(...C.accentText);
          doc.setFontSize(9);
          doc.setFont('helvetica', 'bold');
          doc.text(cleanLine, 22, mdY + 5.5);
          mdY += 11;
        } else if (lvl === 2) {
          doc.setDrawColor(...C.borderMd);
          doc.setLineWidth(0.3);
          doc.line(14, mdY + 6, pageW - 14, mdY + 6);
          doc.setTextColor(...C.textDark);
          doc.setFontSize(8.5);
          doc.setFont('helvetica', 'bold');
          doc.text(cleanLine, 14, mdY + 5);
          mdY += 10;
        } else {
          doc.setTextColor(...C.textBody);
          doc.setFontSize(8);
          doc.setFont('helvetica', 'bold');
          doc.text(cleanLine, 14, mdY + 4.5);
          mdY += 8;
        }
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        // Bullet list
        doc.setFillColor(...C.accent);
        doc.circle(17, mdY + 2.5, 1, 'F');
        doc.setTextColor(...C.textBody);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.text(line.slice(2), 20, mdY + 4);
        mdY += 5.5;
      } else if (line.trim() === '' || line.trim() === '---') {
        mdY += 3;
      } else if (line.startsWith('**') && line.endsWith('**')) {
        // Bold line
        doc.setTextColor(...C.textDark);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(line.replace(/\*\*/g, ''), 14, mdY + 4);
        mdY += 5.5;
      } else {
        // Regular body text
        doc.setTextColor(...C.textBody);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.text(line, 14, mdY + 4);
        mdY += 5;
      }
      li++;
    }
  }

  // ── Save ──────────────────────────────────────────────────────────────────
  const filename = `SecuRAG_Report_${reportTitle.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 40)}_${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
}
