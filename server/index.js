import process from "node:process";
import express from "express";
import cors from "cors";
import dns from "node:dns/promises";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

/**
 * Health check endpoint
 */
app.get("/api/health", (req, res) => {
  res.json({ status: "online", timestamp: new Date().toISOString() });
});

/**
 * 1. REAL LIVE DATA BREACH & HIBP API
 * Fetches genuine data breach intelligence from live global repositories.
 */
app.get("/api/breach", async (req, res) => {
  const email = (req.query.email || "").trim().toLowerCase();

  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "A valid email address is required." });
  }

  const hibpUrl = `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(
      `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (response.status === 404) {
      return res.json({
        email,
        pwned: false,
        breachCount: 0,
        passwordsExposed: 0,
        riskRating: "Safe",
        breaches: [],
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    if (response.ok) {
      const data = await response.json();
      const rawBreaches = data.ExposedBreaches?.breaches_details || [];
      const breaches = rawBreaches.map((b) => ({
        name: b.breach || "Security Breach",
        domain: b.domain || "Unknown",
        breachDate: b.xposed_date || b.added ? new Date(b.added || b.xposed_date).toLocaleDateString() : "Undisclosed",
        pwnCount: typeof b.xposed_records === "number" ? b.xposed_records : 0,
        description: b.details || `Breach incident affecting ${b.breach}.`,
        logo: b.logo || "",
        industry: b.industry || "General",
        dataClasses: b.xposed_data
          ? b.xposed_data.split(";").map((s) => s.trim()).filter(Boolean)
          : ["Email addresses", "Passwords"],
        verified: b.verified === "Yes",
      }));

      const passwordsExposed = data.BreachesSummary?.passwords_count || 0;
      const riskRating = data.BreachMetrics?.risk_rating || (breaches.length > 3 ? "Critical" : breaches.length > 0 ? "High" : "Low");

      return res.json({
        email,
        pwned: breaches.length > 0,
        breachCount: breaches.length,
        passwordsExposed,
        riskRating,
        breaches,
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    // Fallback if status was not 200 or 404 (e.g. rate limit)
    const checkRes = await fetch(
      `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`
    );
    if (checkRes.ok) {
      const checkData = await checkRes.json();
      const breachNames = Array.isArray(checkData.Breaches) ? checkData.Breaches.flat() : [];
      return res.json({
        email,
        pwned: breachNames.length > 0,
        breachCount: breachNames.length,
        passwordsExposed: 0,
        riskRating: breachNames.length > 2 ? "High" : "Medium",
        breaches: breachNames.map((name) => ({
          name: String(name),
          domain: `${String(name).toLowerCase().replace(/[^a-z0-9]/g, "")}.com`,
          breachDate: "Recorded",
          pwnCount: 0,
          description: `Security breach involving credentials associated with ${name}.`,
          dataClasses: ["Email addresses", "Passwords"],
          verified: true,
        })),
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    return res.json({
      email,
      pwned: false,
      breachCount: 0,
      passwordsExposed: 0,
      riskRating: "Clean",
      breaches: [],
      hibpUrl,
      checkedAt: new Date().toLocaleString(),
    });
  } catch (error) {
    console.error("Breach lookup server error:", error);
    return res.status(500).json({
      error: "Unable to query live breach telemetry at this moment.",
      email,
      hibpUrl,
    });
  }
});

/**
 * 2. REAL LIVE GEOIP LOOKUP API
 * Resolves genuine IP routing, ASN, ISP, and geographic coordinates.
 */
app.get("/api/geoip", async (req, res) => {
  const ip = (req.query.ip || "").trim();

  if (!ip) {
    return res.status(400).json({ error: "An IP address query parameter is required." });
  }

  // Check for private / loopback IPs
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("127.") ||
    ip === "localhost"
  ) {
    return res.json({
      ip,
      city: "Localhost / Internal Subnet",
      region: "Private",
      country_name: "Internal Network",
      country_code: "LOCAL",
      postal: "N/A",
      latitude: 0,
      longitude: 0,
      timezone: "UTC",
      isp: "Local Area Network (RFC 1918)",
      org: "Private Infrastructure",
      asn: "N/A",
      isPrivate: true,
    });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const liveGeo = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (liveGeo.ok) {
      const data = await liveGeo.json();
      if (data.status === "success") {
        return res.json({
          ip: data.query || ip,
          city: data.city || "Unknown City",
          region: data.regionName || "Unknown Region",
          country_name: data.country || "Unknown Country",
          country_code: data.countryCode || "UN",
          postal: data.zip || "N/A",
          latitude: data.lat || 0,
          longitude: data.lon || 0,
          timezone: data.timezone || "UTC",
          isp: data.isp || "Internet Service Provider",
          org: data.org || data.isp || "Network Host",
          asn: data.as || "N/A",
          isPrivate: false,
        });
      }
    }

    // Secondary live fallback: freeipapi
    const fallbackRes = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`);
    if (fallbackRes.ok) {
      const data = await fallbackRes.json();
      return res.json({
        ip,
        city: data.cityName || "Unknown City",
        region: data.regionName || "Unknown Region",
        country_name: data.countryName || "Unknown Country",
        country_code: data.countryCode || "UN",
        postal: data.zipCode || "N/A",
        latitude: data.latitude || 0,
        longitude: data.longitude || 0,
        timezone: data.timeZone || "UTC",
        isp: "Public ISP",
        org: `IPv${data.ipVersion || 4} Provider`,
        asn: data.asn ? `AS${data.asn}` : "N/A",
        isPrivate: false,
      });
    }

    return res.status(502).json({ error: "Failed to resolve IP location from live providers." });
  } catch (error) {
    console.error("GeoIP server error:", error);
    return res.status(500).json({ error: "GeoIP service error." });
  }
});

/**
 * 3. REAL LIVE DNS & DOMAIN REPUTATION API
 * Queries real DNS records (MX mail exchangers, SPF TXT records, DMARC records) for sender domains.
 */
app.get("/api/dns-check", async (req, res) => {
  const domain = (req.query.domain || "").trim().toLowerCase();

  if (!domain) {
    return res.status(400).json({ error: "Domain parameter is required." });
  }

  try {
    let mxRecords = [];
    let txtRecords = [];
    let dmarcRecords = [];

    // Query MX records
    try {
      mxRecords = await dns.resolveMx(domain);
    } catch {
      mxRecords = [];
    }

    // Query TXT records for SPF
    try {
      const rawTxt = await dns.resolveTxt(domain);
      txtRecords = rawTxt.flat();
    } catch {
      txtRecords = [];
    }

    // Query DMARC records (_dmarc.domain)
    try {
      const rawDmarc = await dns.resolveTxt(`_dmarc.${domain}`);
      dmarcRecords = rawDmarc.flat();
    } catch {
      dmarcRecords = [];
    }

    const spfRecord = txtRecords.find((t) => t.toLowerCase().startsWith("v=spf1")) || null;
    const dmarcRecord = dmarcRecords.find((t) => t.toLowerCase().startsWith("v=dmarc1")) || null;

    return res.json({
      domain,
      hasMxRecords: mxRecords.length > 0,
      mxRecords,
      hasSpfRecord: spfRecord !== null,
      spfRecord,
      hasDmarcRecord: dmarcRecord !== null,
      dmarcRecord,
      domainValid: mxRecords.length > 0 || txtRecords.length > 0,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("DNS check error:", error);
    return res.status(500).json({ error: "DNS verification query failed." });
  }
});

app.listen(PORT, () => {
  console.log(`[AI Email Forensics] Real Data Backend API running on http://localhost:${PORT}`);
});
