import { useState } from "react";
import {
  Upload,
  FileText,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Link2,
  Mail,
  Hash,
  Paperclip,
  Code,
} from "lucide-react";
import { analyzeEmlFile } from "../services/emailAnalyzer";

export default function AnalyzeEmail({
  file,
  setFile,
  analysis,
  onAnalysisComplete,
  onBack,
  settings,
}) {
  const [analyzing, setAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState("overview"); // overview, headers, body, links

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];
    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith(".eml")) {
      alert("Please select a valid .eml email file.");
      return;
    }

    setFile(selectedFile);
  };

  const handleAnalyze = async () => {
    if (!file) {
      alert("Please choose an .eml file first.");
      return;
    }

    setAnalyzing(true);
    try {
      const result = await analyzeEmlFile(file, settings);
      if (onAnalysisComplete) {
        onAnalysisComplete(result);
      }
    } catch (error) {
      console.error("Email analysis failed:", error);
      alert("Unable to analyze this email file. Please ensure it is a valid .eml file.");
    } finally {
      setAnalyzing(false);
    }
  };

  const getRiskClass = () => {
    if (!analysis) return "";
    if (analysis.riskScore >= 70) return "risk-high";
    if (analysis.riskScore >= 40) return "risk-medium";
    return "risk-low";
  };

  return (
    <div className="analyze-page">
      <div className="analyze-header">
        <button className="analyze-back" onClick={onBack}>
          <span className="back-arrow">←</span>
          <span>Dashboard</span>
        </button>

        <div className="analyze-title">
          <div className="title-icon">
            <AlertTriangle size={24} />
          </div>

          <div>
            <p className="eyebrow">EMAIL FORENSICS</p>
            <h1>Analyze Suspicious Email</h1>
            <p className="page-description">
              Upload an email file to detect phishing indicators, suspicious
              links, authentication failures, and other security threats.
            </p>
          </div>
        </div>
      </div>

      <div className="analyze-grid">
        {/* UPLOAD CARD */}
        <section className="analyze-card upload-card">
          <div className="card-heading">
            <div className="icon-box blue">
              <Upload size={22} />
            </div>
            <div>
              <h2>Upload Email</h2>
              <p>Select an .eml file for analysis</p>
            </div>
          </div>

          <label className="upload-zone">
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={handleFileChange}
              hidden
            />
            <Upload size={42} />
            <strong>
              {file ? file.name : "Drop your .eml file here"}
            </strong>
            <span>
              {file
                ? `${(file.size / 1024).toFixed(1)} KB selected`
                : "or click to browse from your computer"}
            </span>
          </label>

          <button
            className="primary-button"
            onClick={handleAnalyze}
            disabled={!file || analyzing}
            style={{ width: "100%" }}
          >
            {analyzing ? "Analyzing..." : "Analyze Email"}
          </button>
        </section>

        {/* SECURITY ANALYSIS CARD */}
        <section className="analyze-card">
          <div className="card-heading">
            <div className="icon-box purple">
              <ShieldCheck size={22} />
            </div>
            <div>
              <h2>Security Analysis</h2>
              <p>Threat assessment results</p>
            </div>
          </div>

          {!analysis ? (
            <div className="empty-analysis">
              <FileText size={48} />
              <h3>No analysis available</h3>
              <p>
                Upload an email and click Analyze Email to view security
                indicators.
              </p>
            </div>
          ) : (
            <div className="analysis-result">
              <div className="risk-score">
                <span>Threat Risk Score</span>
                <strong>{analysis.riskScore}</strong>
                <small>/ 100</small>
              </div>

              <div className={getRiskClass()}>
                {analysis.riskScore >= 70 ? (
                  <AlertTriangle size={18} />
                ) : (
                  <ShieldCheck size={18} />
                )}
                {analysis.riskLevel}
              </div>

              <div className="indicator-row">
                <div>
                  <AlertTriangle size={18} />
                  <span>Phishing Indicators</span>
                </div>
                <strong>
                  {analysis.phishingDetected
                    ? `${analysis.detectedKeywords.length} Detected`
                    : "Not Detected"}
                </strong>
              </div>

              <div className="indicator-row">
                <div>
                  <Link2 size={18} />
                  <span>Suspicious Links</span>
                </div>
                <strong>
                  {analysis.suspiciousLinks > 0
                    ? `${analysis.suspiciousLinks} Found`
                    : "None"}
                </strong>
              </div>

              <div className="indicator-row">
                <div>
                  <Mail size={18} />
                  <span>Total Links</span>
                </div>
                <strong>{analysis.totalLinks}</strong>
              </div>

              <div className="indicator-row">
                <div>
                  <Hash size={18} />
                  <span>SHA-256 Checksum</span>
                </div>
                <strong style={{ fontFamily: "monospace", fontSize: "11px" }}>
                  {analysis.sha256 ? analysis.sha256.substring(0, 16) + "..." : "Computed"}
                </strong>
              </div>

              <div className="indicator-row">
                <div>
                  <CheckCircle2 size={18} />
                  <span>File Analysis</span>
                </div>
                <strong>Completed</strong>
              </div>
            </div>
          )}
        </section>
      </div>

      {/* DETAILS CARD WITH TABS */}
      {analysis && (
        <section className="analyze-card details-card" style={{ marginTop: "24px" }}>
          <div className="card-heading" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div className="icon-box green">
                <FileText size={22} />
              </div>
              <div>
                <h2>Email Forensic Details</h2>
                <p>Information extracted from the submitted email</p>
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px" }}>
              <button
                className={`secondary-button ${activeTab === "overview" ? "active-tab" : ""}`}
                onClick={() => setActiveTab("overview")}
                style={{ padding: "6px 14px", fontSize: "13px" }}
              >
                Overview
              </button>
              <button
                className={`secondary-button ${activeTab === "links" ? "active-tab" : ""}`}
                onClick={() => setActiveTab("links")}
                style={{ padding: "6px 14px", fontSize: "13px" }}
              >
                Links ({analysis.totalLinks})
              </button>
              <button
                className={`secondary-button ${activeTab === "headers" ? "active-tab" : ""}`}
                onClick={() => setActiveTab("headers")}
                style={{ padding: "6px 14px", fontSize: "13px" }}
              >
                Headers ({analysis.headers?.length || 0})
              </button>
              <button
                className={`secondary-button ${activeTab === "body" ? "active-tab" : ""}`}
                onClick={() => setActiveTab("body")}
                style={{ padding: "6px 14px", fontSize: "13px" }}
              >
                Body Text
              </button>
            </div>
          </div>

          {activeTab === "overview" && (
            <>
              <div className="details-grid">
                <div>
                  <span>File Name</span>
                  <strong>{analysis.fileName}</strong>
                </div>

                <div>
                  <span>File Size</span>
                  <strong>{(analysis.fileSize / 1024).toFixed(1)} KB</strong>
                </div>

                <div>
                  <span>From</span>
                  <strong>{analysis.from}</strong>
                </div>

                <div>
                  <span>To</span>
                  <strong>{analysis.to}</strong>
                </div>

                <div>
                  <span>Subject</span>
                  <strong>{analysis.subject}</strong>
                </div>

                <div>
                  <span>Threat Level</span>
                  <strong
                    className={
                      analysis.riskScore >= 70
                        ? "danger"
                        : analysis.riskScore >= 40
                        ? "warning"
                        : "success"
                    }
                  >
                    {analysis.riskLevel}
                  </strong>
                </div>

                <div>
                  <span>SPF</span>
                  <strong
                    className={
                      analysis.spf === "Fail"
                        ? "danger"
                        : analysis.spf === "Pass"
                        ? "success"
                        : "warning"
                    }
                  >
                    {analysis.spf}
                  </strong>
                </div>

                <div>
                  <span>DKIM</span>
                  <strong
                    className={
                      analysis.dkim === "Fail"
                        ? "danger"
                        : analysis.dkim === "Pass"
                        ? "success"
                        : "warning"
                    }
                  >
                    {analysis.dkim}
                  </strong>
                </div>

                <div>
                  <span>DMARC</span>
                  <strong
                    className={
                      analysis.dmarc === "Fail"
                        ? "danger"
                        : analysis.dmarc === "Pass"
                        ? "success"
                        : "warning"
                    }
                  >
                    {analysis.dmarc}
                  </strong>
                </div>

                <div>
                  <span>Attachments</span>
                  <strong>{analysis.attachmentCount}</strong>
                </div>
              </div>

              {analysis.detectedKeywords?.length > 0 && (
                <div
                  style={{
                    marginTop: "20px",
                    padding: "16px",
                    borderRadius: "10px",
                    background: "#fff7ed",
                    border: "1px solid #ffedd5",
                  }}
                >
                  <strong style={{ color: "#c2410c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <AlertTriangle size={16} /> Detected Security Keywords
                  </strong>
                  <p style={{ marginTop: "6px", color: "#9a3412" }}>
                    {analysis.detectedKeywords.join(", ")}
                  </p>
                </div>
              )}

              {analysis.hasAttachments && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "16px",
                    borderRadius: "10px",
                    background: "#fff1f2",
                    border: "1px solid #ffe4e6",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#be123c", fontWeight: "600" }}>
                    <Paperclip size={16} />
                    <span>Email contains {analysis.attachmentCount} attachment(s):</span>
                  </div>
                  <ul style={{ marginTop: "8px", paddingLeft: "20px", color: "#9f1239" }}>
                    {analysis.attachments?.map((att, i) => (
                      <li key={i}>
                        {att.filename} ({(att.size / 1024).toFixed(1)} KB) - {att.mimeType}
                        {att.isExecutable && <strong style={{ color: "#dc2626" }}> [EXECUTABLE / HIGH RISK]</strong>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          {activeTab === "links" && (
            <div style={{ marginTop: "16px" }}>
              {analysis.allUrls?.length === 0 ? (
                <p>No URLs or hyperlinks found in this email.</p>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                      <th style={{ padding: "8px 4px" }}>URL</th>
                      <th style={{ padding: "8px 4px" }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.allUrls?.map((url, idx) => {
                      const isSuspicious = analysis.suspiciousLinksList?.includes(url);
                      return (
                        <tr key={idx} style={{ borderBottom: "1px solid #f1f5f9" }}>
                          <td style={{ padding: "8px 4px", wordBreak: "break-all", fontFamily: "monospace" }}>
                            {url}
                          </td>
                          <td style={{ padding: "8px 4px" }}>
                            <span
                              style={{
                                padding: "3px 8px",
                                borderRadius: "6px",
                                fontSize: "11px",
                                fontWeight: "600",
                                background: isSuspicious ? "#fee2e2" : "#dcfce7",
                                color: isSuspicious ? "#b91c1c" : "#15803d",
                              }}
                            >
                              {isSuspicious ? "Suspicious" : "Clean"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {activeTab === "headers" && (
            <div style={{ marginTop: "16px", maxHeight: "400px", overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", fontFamily: "monospace" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                    <th style={{ padding: "6px 4px", width: "200px" }}>Header Key</th>
                    <th style={{ padding: "6px 4px" }}>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.headers?.map((h, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #f1f5f9" }}>
                      <td style={{ padding: "6px 4px", fontWeight: "600", color: "#334155" }}>{h.key}</td>
                      <td style={{ padding: "6px 4px", color: "#64748b", wordBreak: "break-all" }}>{h.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "body" && (
            <div style={{ marginTop: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "8px", color: "#475569" }}>
                <Code size={16} />
                <strong>Extracted Body Text:</strong>
              </div>
              <pre
                style={{
                  background: "#f8fafc",
                  padding: "16px",
                  borderRadius: "8px",
                  border: "1px solid #e2e8f0",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  fontSize: "12px",
                  color: "#1e293b",
                  maxHeight: "350px",
                  overflowY: "auto",
                }}
              >
                {analysis.bodyPreview}
              </pre>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
