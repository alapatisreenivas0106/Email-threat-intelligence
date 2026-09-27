import {
  Download,
  FileText,
  FileCode,
  Printer,
  FileSearch,
} from "lucide-react";
import ModulePage from "../components/ModulePage";

export default function Reports({ analysis, setActivePage }) {
  const downloadTextReport = () => {
    if (!analysis) return;

    const report = `================================================================================
AI EMAIL FORENSICS INCIDENT & THREAT INTELLIGENCE REPORT
================================================================================
Generated At: ${new Date().toLocaleString()}
Evidence ID : ${analysis.id}
File Name   : ${analysis.fileName}
File Size   : ${(analysis.fileSize / 1024).toFixed(1)} KB
SHA-256     : ${analysis.sha256}

--------------------------------------------------------------------------------
1. EXECUTIVE SUMMARY & RISK ASSESSMENT
--------------------------------------------------------------------------------
Threat Risk Score: ${analysis.riskScore} / 100
Threat Risk Level: ${analysis.riskLevel}
Phishing Detected: ${analysis.phishingDetected ? "YES (CRITICAL)" : "NO"}
Suspicious Links : ${analysis.suspiciousLinks} Flagged
Total Attachments: ${analysis.attachmentCount}

--------------------------------------------------------------------------------
2. EMAIL METADATA & HEADERS
--------------------------------------------------------------------------------
Subject  : ${analysis.subject}
From     : ${analysis.from}
To       : ${analysis.to}
Date     : ${analysis.date}
MessageID: ${analysis.messageId}

--------------------------------------------------------------------------------
3. EMAIL AUTHENTICATION AUDIT
--------------------------------------------------------------------------------
SPF Status  : ${analysis.spf}
DKIM Status : ${analysis.dkim}
DMARC Status: ${analysis.dmarc}
Auth Header : ${analysis.authenticationResults}

--------------------------------------------------------------------------------
4. THREAT INDICATORS & DETECTED KEYWORDS
--------------------------------------------------------------------------------
Detected Keywords: ${analysis.detectedKeywords?.join(", ") || "None"}
Suspicious URLs  :
${analysis.suspiciousLinksList?.map((u) => `  * ${u}`).join("\n") || "  (None)"}

Extracted IPs from Hops:
${analysis.extractedIPs?.map((ip) => `  * ${ip}`).join("\n") || "  (None)"}

--------------------------------------------------------------------------------
5. ATTACHMENT AUDIT
--------------------------------------------------------------------------------
${analysis.attachments?.map((a) => `  * ${a.filename} (${(a.size / 1024).toFixed(1)} KB) - ${a.mimeType} ${a.isExecutable ? "[EXECUTABLE]" : ""}`).join("\n") || "  (No attachments)"}

================================================================================
END OF FORENSIC REPORT - INTEGRITY PRESERVED
================================================================================
`;

    const blob = new Blob([report], { type: "text/plain;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `forensics-report-${analysis.fileName.replace(/\.eml$/i, "")}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadJSONReport = () => {
    if (!analysis) return;
    const jsonStr = JSON.stringify(analysis, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `forensics-dump-${analysis.fileName.replace(/\.eml$/i, "")}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const printReport = () => {
    window.print();
  };

  return (
    <ModulePage
      title="Forensic Reports"
      subtitle="Generate, preview, and export comprehensive threat analysis & chain of custody documentation."
      icon={<Download size={28} />}
    >
      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <FileText size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Analyzed Evidence</h3>
          <p>Please analyze an email to generate and export forensic reports.</p>
          <button
            className="primary-button"
            style={{ marginTop: "16px" }}
            onClick={() => setActivePage("dashboard")}
          >
            <FileSearch size={16} /> Go to Dashboard
          </button>
        </div>
      ) : (
        <>
          {/* ACTIONS TOOLBAR */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
              <div>
                <strong>Report for: {analysis.fileName}</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Evidence SHA-256: {analysis.sha256.substring(0, 16)}...
                </span>
              </div>

              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <button className="primary-button" onClick={downloadTextReport}>
                  <FileText size={16} /> Download .TXT
                </button>

                <button className="secondary-button" onClick={downloadJSONReport}>
                  <FileCode size={16} /> Download .JSON
                </button>

                <button className="secondary-button" onClick={printReport}>
                  <Printer size={16} /> Print / Save PDF
                </button>
              </div>
            </div>
          </div>

          {/* REPORT PREVIEW */}
          <div className="panel print-container" style={{ background: "#ffffff", padding: "30px", borderRadius: "10px" }}>
            <div style={{ borderBottom: "2px solid #0f172a", paddingBottom: "16px", marginBottom: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <h2 style={{ fontSize: "22px", color: "#0f172a" }}>AI EMAIL FORENSIC INCIDENT REPORT</h2>
                  <span style={{ fontSize: "13px", color: "#64748b" }}>Automated Security Operations & Threat Intelligence</span>
                </div>
                <div
                  style={{
                    padding: "8px 16px",
                    borderRadius: "8px",
                    fontWeight: "800",
                    fontSize: "14px",
                    background:
                      analysis.riskScore >= 70
                        ? "#fee2e2"
                        : analysis.riskScore >= 40
                        ? "#fef3c7"
                        : "#dcfce7",
                    color:
                      analysis.riskScore >= 70
                        ? "#b91c1c"
                        : analysis.riskScore >= 40
                        ? "#b45309"
                        : "#15803d",
                  }}
                >
                  {analysis.riskScore}/100 - {analysis.riskLevel}
                </div>
              </div>
            </div>

            {/* METADATA TABLE */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px", marginBottom: "24px" }}>
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Evidence File:</span>
                <strong style={{ display: "block" }}>{analysis.fileName}</strong>
              </div>
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Sender:</span>
                <strong style={{ display: "block" }}>{analysis.from}</strong>
              </div>
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Subject:</span>
                <strong style={{ display: "block" }}>{analysis.subject}</strong>
              </div>
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Date / Timestamp:</span>
                <strong style={{ display: "block" }}>{analysis.date}</strong>
              </div>
            </div>

            {/* AUTH STATUS */}
            <h4 style={{ marginBottom: "12px", color: "#1e293b" }}>Authentication Audit</h4>
            <div style={{ display: "flex", gap: "16px", marginBottom: "24px", flexWrap: "wrap" }}>
              <div style={{ padding: "10px 16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>SPF: </span>
                <strong>{analysis.spf}</strong>
              </div>
              <div style={{ padding: "10px 16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>DKIM: </span>
                <strong>{analysis.dkim}</strong>
              </div>
              <div style={{ padding: "10px 16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>DMARC: </span>
                <strong>{analysis.dmarc}</strong>
              </div>
            </div>

            {/* THREAT FINDINGS */}
            <h4 style={{ marginBottom: "12px", color: "#1e293b" }}>Key Threat Findings</h4>
            <ul style={{ paddingLeft: "20px", color: "#334155", lineHeight: "1.8" }}>
              <li>
                Phishing keywords:{" "}
                <strong>{analysis.detectedKeywords?.length > 0 ? analysis.detectedKeywords.join(", ") : "None detected"}</strong>
              </li>
              <li>
                Suspicious URLs:{" "}
                <strong>{analysis.suspiciousLinks > 0 ? `${analysis.suspiciousLinks} URLs flagged` : "None flagged"}</strong>
              </li>
              <li>
                Attachments:{" "}
                <strong>{analysis.attachmentCount} attachment(s) found</strong>
              </li>
            </ul>

            <div style={{ marginTop: "30px", paddingTop: "16px", borderTop: "1px solid #e2e8f0", fontSize: "12px", color: "#94a3b8", display: "flex", justifyContent: "space-between" }}>
              <span>SHA-256 Digest: {analysis.sha256}</span>
              <span>Report Generated by AI Email Forensics Engine</span>
            </div>
          </div>
        </>
      )}
    </ModulePage>
  );
}
