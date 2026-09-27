import {
  AlertTriangle,
  FileSearch,
  Hash,
  Link2,
  Lock,
  Mail,
  ShieldAlert,
  ShieldCheck,
  Tag,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import StatCard from "../components/StatCard";

export default function ThreatIntelligence({ analysis, setActivePage }) {
  const senderDomain = analysis?.from?.includes("@")
    ? analysis.from.split("@")[1].replace(/[<>]/g, "").trim()
    : "Unknown";

  return (
    <ModulePage
      title="Threat Intelligence"
      subtitle="Extracted Indicators of Compromise (IoC), domain spoofing analysis, and phishing telemetry."
      icon={<ShieldAlert size={28} />}
    >
      <div className="stat-grid" style={{ marginBottom: "24px" }}>
        <StatCard
          icon={<AlertTriangle />}
          label="Phishing Assessment"
          value={analysis?.phishingDetected ? "Detected" : analysis ? "Clean" : "None"}
          change="Heuristic model"
          danger={analysis?.phishingDetected}
          success={analysis && !analysis?.phishingDetected}
        />

        <StatCard
          icon={<Link2 />}
          label="Suspicious Links"
          value={analysis?.suspiciousLinks ?? 0}
          change={analysis?.suspiciousLinks > 0 ? "Flagged URLs" : "Safe"}
          warning={analysis?.suspiciousLinks > 0}
          success={analysis && analysis.suspiciousLinks === 0}
        />

        <StatCard
          icon={<Hash />}
          label="Threat Risk Score"
          value={analysis?.riskScore ? `${analysis.riskScore}/100` : "0/100"}
          change={analysis?.riskLevel || "No scan"}
          purple
        />

        <StatCard
          icon={<Lock />}
          label="Auth Integrity"
          value={
            analysis?.spf === "Pass" && analysis?.dkim === "Pass"
              ? "Verified"
              : analysis
              ? "Degraded"
              : "Waiting"
          }
          change={analysis ? `SPF:${analysis.spf}` : "Idle"}
          success={analysis?.spf === "Pass" && analysis?.dkim === "Pass"}
          warning={analysis && (analysis.spf !== "Pass" || analysis.dkim !== "Pass")}
        />
      </div>

      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <ShieldAlert size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Threat Intelligence Data</h3>
          <p>Scan an email via Dashboard or Analyze Email to populate IoC feeds and threat indicators.</p>
          <button
            className="primary-button"
            style={{ marginTop: "16px" }}
            onClick={() => setActivePage("dashboard")}
          >
            <FileSearch size={16} /> Go to Dashboard
          </button>
        </div>
      ) : (
        <div className="main-grid">
          {/* SENDER & DOMAIN SPOOF ANALYSIS */}
          <div className="panel" style={{ gridColumn: "1 / -1" }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Mail size={18} /> Sender & Domain Intelligence
            </h3>
            <p>Verification of sender reputation and domain alignment.</p>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "16px",
                marginTop: "16px",
                background: "#f8fafc",
                padding: "16px",
                borderRadius: "8px",
              }}
            >
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Sender Address:</span>
                <strong style={{ display: "block", color: "#1e293b", fontSize: "14px" }}>
                  {analysis.from}
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Extracted Domain:</span>
                <strong style={{ display: "block", color: "#1e293b", fontSize: "14px" }}>
                  {senderDomain}
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>DMARC Policy Enforcement:</span>
                <strong
                  style={{
                    display: "block",
                    color: analysis.dmarc === "Pass" ? "#16a34a" : analysis.dmarc === "Fail" ? "#dc2626" : "#ca8a04",
                    fontSize: "14px",
                  }}
                >
                  {analysis.dmarc}
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Evidence Checksum:</span>
                <strong style={{ display: "block", color: "#64748b", fontFamily: "monospace", fontSize: "12px" }}>
                  {analysis.sha256.substring(0, 18)}...
                </strong>
              </div>
            </div>
          </div>

          {/* DETECTED PHISHING KEYWORDS */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Tag size={18} /> Phishing Indicators & Keywords
            </h3>
            <p>Suspicious urgency, credential harvesting, or financial triggers.</p>

            {analysis.detectedKeywords?.length === 0 ? (
              <div style={{ marginTop: "16px", color: "#16a34a", display: "flex", alignItems: "center", gap: "6px" }}>
                <ShieldCheck size={16} /> No high-risk phishing keywords matched.
              </div>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "16px" }}>
                {analysis.detectedKeywords.map((kw, i) => (
                  <span
                    key={i}
                    style={{
                      padding: "6px 12px",
                      background: "#fee2e2",
                      color: "#b91c1c",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "600",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    <AlertTriangle size={12} /> {kw}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* SUSPICIOUS LINKS */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Link2 size={18} /> Suspicious Link Analysis
            </h3>
            <p>Extracted URLs matching risk criteria or shortener patterns.</p>

            {analysis.suspiciousLinksList?.length === 0 ? (
              <div style={{ marginTop: "16px", color: "#16a34a", display: "flex", alignItems: "center", gap: "6px" }}>
                <ShieldCheck size={16} /> No suspicious URLs flagged.
              </div>
            ) : (
              <ul style={{ marginTop: "12px", paddingLeft: "18px", color: "#b91c1c", fontSize: "13px" }}>
                {analysis.suspiciousLinksList?.map((link, i) => (
                  <li key={i} style={{ wordBreak: "break-all", marginBottom: "6px", fontFamily: "monospace" }}>
                    {link}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </ModulePage>
  );
}
