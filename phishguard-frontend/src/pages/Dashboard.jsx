import { useEffect, useState } from "react";
import { getScanHistory } from "../utils/historyStorage";

function getScanClass(item) {
  if (item.prediction === "Phishing") {
    return "danger";
  }

  if (item.riskLevel && item.riskLevel !== "safe") {
    return "warning";
  }

  return "safe";
}

function getScanLabel(item) {
  if (item.prediction === "Phishing") {
    return "Fake";
  }

  if (item.riskLevel && item.riskLevel !== "safe") {
    return "Suspicious";
  }

  return "Safe";
}

function Dashboard() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  const totalScans = history.length;
  const safeCount = history.filter((item) => item.prediction === "Safe").length;
  const phishingCount = history.filter((item) => item.prediction === "Phishing").length;
  const highRiskCount = history.filter((item) => item.riskLevel === "high").length;
  const mediumRiskCount = history.filter((item) => item.riskLevel === "medium").length;
  const lowRiskCount = history.filter(
    (item) => item.riskLevel === "low" || item.riskLevel === "safe"
  ).length;

  const recentScans = history.slice(0, 5);

  return (
    <main className="app">
      <section className="page-header">
        <p className="tag">DASHBOARD</p>
        <h1>Scan Statistics</h1>
        <p className="subtitle">
          Overview of URLs analyzed by PhishGuard on this device.
        </p>
      </section>

      <section className="stats-grid">
        <div className="stat-card">
          <span>Total Scans</span>
          <strong>{totalScans}</strong>
        </div>

        <div className="stat-card safe">
          <span>Safe URLs</span>
          <strong>{safeCount}</strong>
        </div>

        <div className="stat-card danger">
          <span>Phishing URLs</span>
          <strong>{phishingCount}</strong>
        </div>

        <div className="stat-card">
          <span>Low Risk</span>
          <strong>{lowRiskCount}</strong>
        </div>

        <div className="stat-card warning">
          <span>Medium Risk</span>
          <strong>{mediumRiskCount}</strong>
        </div>

        <div className="stat-card danger">
          <span>High Risk</span>
          <strong>{highRiskCount}</strong>
        </div>
      </section>

      <section className="recent-section">
        <h2>Recent Scans</h2>

        {recentScans.length === 0 ? (
          <div className="empty-card">
            <p>No scan data yet. Scan a URL first.</p>
          </div>
        ) : (
          <div className="recent-list">
            {recentScans.map((item) => (
              <article className={`recent-card ${getScanClass(item)}`} key={item.id}>
                <div>
                  <strong>{getScanLabel(item)}</strong>
                  <p>{item.url}</p>
                </div>

                <span>{item.confidence}%</span>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

export default Dashboard;
