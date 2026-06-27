import React from 'react';

interface ThreatCardProps {
  cve: {
    cve_id: string;
    description: string;
    cvss_score: number | null;
    published_date: string | null;
    affected_tech: string | null;
  };
  lang: "ar" | "en";
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#E74C3C", 
  high: "#E67E22", 
  medium: "#F1C40F", 
  low: "#2ECC71",
  none: "#A8A8C4"
};

export default function ThreatCard({ cve, lang }: ThreatCardProps) {
  const getSeverity = (score: number | null) => {
    if (score === null) return "none";
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  };

  const severity = getSeverity(cve.cvss_score);
  const color = SEVERITY_COLOR[severity];

  return (
    <div 
      style={{ 
        background: "#12121E", 
        border: `1px solid ${color}22`, 
        borderLeft: `4px solid ${color}`, 
        borderRadius: 12, 
        padding: "18px 20px", 
        transition: "transform 0.15s ease",
        display: "flex",
        flexDirection: "column",
        gap: 12
      }}
      onMouseEnter={(e) => ((e.currentTarget as HTMLDivElement).style.transform = "translateY(-2px)")}
      onMouseLeave={(e) => ((e.currentTarget as HTMLDivElement).style.transform = "translateY(0)")}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
        <a 
          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} 
          target="_blank" 
          rel="noopener noreferrer"
          style={{ color: "#C9A84C", fontSize: 16, fontWeight: 800, textDecoration: "none" }}
        >
          {cve.cve_id} ↗
        </a>
        <div style={{ display: "flex", gap: 6 }}>
          {cve.cvss_score !== null && (
            <span style={{ background: `${color}20`, color, padding: "2px 10px", borderRadius: 99, fontSize: 11, fontWeight: 800, textTransform: "uppercase" }}>
              CVSS: {cve.cvss_score.toFixed(1)} ({severity})
            </span>
          )}
          {cve.affected_tech && (
            <span style={{ background: "#C9A84C12", color: "#C9A84C88", padding: "2px 10px", borderRadius: 99, fontSize: 11, fontWeight: 700 }}>
              {cve.affected_tech.toUpperCase()}
            </span>
          )}
        </div>
      </div>
      
      <p style={{ color: "#A8A8C4", fontSize: 13, lineHeight: 1.6, margin: 0 }}>
        {cve.description.length > 200 ? cve.description.slice(0, 200) + '...' : cve.description}
      </p>
      
      {cve.published_date && (
        <p style={{ color: "#555577", fontSize: 11, margin: "auto 0 0", fontFamily: "monospace" }}>
          {lang === "ar" ? "نُشر في: " : "Published: "} {new Date(cve.published_date).toLocaleDateString()}
        </p>
      )}
    </div>
  );
}
