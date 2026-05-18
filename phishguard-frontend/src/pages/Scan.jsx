import { useState } from "react";
import { scanUrl } from "../api/phishguardApi";
import { saveScanResult } from "../utils/historyStorage";

function formatPercent(value) {
  if (typeof value !== "number") {
    return "N/A";
  }

  return `${Math.round(value * 100)}%`;
}

function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!url.trim()) {
      setError("Enter a URL to scan.");
      return;
    }

    setIsLoading(true);

    try {
      const data = await scanUrl(url);
      setResult(data);
      saveScanResult(data);
    } catch (scanError) {
      setError(scanError.message || "Unable to scan this URL.");
    } finally {
      setIsLoading(false);
    }
  }

  const flags = result?.url_features?.suspicious_flags || [];
  const resultClass = result?.is_phishing ? "danger" : "safe";

  return (
    <main className="app">
      <p className="tag">URL SCANNER</p>
      <h1>Scan a suspicious link.</h1>
      <p className="subtitle">
        Submit a URL and PhishGuard will check its phishing probability, risk level, and suspicious URL signals.
      </p>

      <section className="scanner-card">
        <form onSubmit={handleSubmit}>
          <label htmlFor="url">URL to analyze</label>
          <input
            id="url"
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            autoComplete="url"
          />
          <button type="submit" disabled={isLoading}>
            {isLoading ? "Scanning..." : "Scan URL"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}
      </section>

      {result && (
        <section className={`result-card ${resultClass}`}>
          <h2>{result.prediction === "phishing" ? "Phishing detected" : "Likely legitimate"}</h2>
          <p className="subtitle">{result.url}</p>

          <div className="result-grid">
            <div>
              <span>Risk Level</span>
              <strong>{result.risk_level}</strong>
            </div>
            <div>
              <span>Phishing Confidence</span>
              <strong>{formatPercent(result.confidence?.phishing)}</strong>
            </div>
            <div>
              <span>Legitimate Confidence</span>
              <strong>{formatPercent(result.confidence?.legitimate)}</strong>
            </div>
            <div>
              <span>Inference Time</span>
              <strong>{result.meta?.inference_time_ms ?? "N/A"} ms</strong>
            </div>
          </div>

          <div className="flags">
            <h3>Suspicious Signals</h3>
            {flags.length > 0 ? (
              <ul>
                {flags.map((flag) => (
                  <li key={flag}>{flag}</li>
                ))}
              </ul>
            ) : (
              <p>No obvious URL structure warnings were found.</p>
            )}
          </div>

          <div className="recommendation">
            <h3>Recommendation</h3>
            <p>
              {result.is_phishing
                ? "Do not open this link or enter credentials. Verify the sender through a trusted channel."
                : "This link appears lower risk, but still verify the domain before sharing sensitive information."}
            </p>
          </div>
        </section>
      )}
    </main>
  );
}

export default Scan;
