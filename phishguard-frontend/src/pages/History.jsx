import { useEffect, useState } from "react";
import { clearScanHistory, getScanHistory } from "../utils/historyStorage";

function getHistoryClass(item) {
  if (item.prediction === "Phishing") {
    return "danger";
  }

  if (item.riskLevel && item.riskLevel !== "safe") {
    return "warning";
  }

  return "safe";
}

function getHistoryLabel(item) {
  if (item.prediction === "Phishing") {
    return "Fake";
  }

  if (item.riskLevel && item.riskLevel !== "safe") {
    return "Suspicious";
  }

  return "Safe";
}

function History() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  function handleClearHistory() {
    clearScanHistory();
    setHistory([]);
  }

  return (
    <main className="app">
      <section className="page-header">
        <p className="tag">SCAN HISTORY</p>
        <h1>Previous Scans</h1>
        <p className="subtitle">
          Review the URLs you scanned using PhishGuard.
        </p>

        {history.length > 0 && (
          <button className="clear-button" onClick={handleClearHistory}>
            Clear History
          </button>
        )}
      </section>

      {history.length === 0 ? (
        <div className="empty-card">
          <h2>No scans yet</h2>
          <p>Scan a URL first to see your history here.</p>
        </div>
      ) : (
        <section className="history-list">
          {history.map((item) => (
            <article
              className={`history-card ${getHistoryClass(item)}`}
              key={item.id}
            >
              <div>
                <h3>{getHistoryLabel(item)}</h3>
                <p className="url-text">{item.url}</p>
                <p className="muted">Domain: {item.domain}</p>
                <p className="muted">Scanned: {item.scannedAt}</p>
              </div>

              <div className="history-meta">
                <span>Risk: {item.riskLevel}</span>
                <span>Confidence: {item.confidence}%</span>
              </div>
            </article>
          ))}
        </section>
      )}
    </main>
  );
}

export default History;
