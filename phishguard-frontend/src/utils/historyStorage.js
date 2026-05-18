const HISTORY_KEY = "phishguard_scan_history";

export function getScanHistory() {
  const savedHistory = localStorage.getItem(HISTORY_KEY);

  if (!savedHistory) {
    return [];
  }

  try {
    const parsedHistory = JSON.parse(savedHistory);
    return Array.isArray(parsedHistory) ? parsedHistory : [];
  } catch {
    return [];
  }
}

export function saveScanResult(result) {
  const history = getScanHistory();

  const confidencePercent = result.is_phishing
    ? Math.round(result.confidence.phishing * 100)
    : Math.round(result.confidence.legitimate * 100);

  const newScan = {
    id: crypto.randomUUID(),
    url: result.url,
    prediction: result.is_phishing ? "Phishing" : "Safe",
    riskLevel: result.risk_level,
    confidence: confidencePercent,
    domain: result.url_features?.domain || "N/A",
    flags: result.url_features?.suspicious_flags || [],
    scannedAt: new Date().toLocaleString(),
  };

  const updatedHistory = [newScan, ...history];
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updatedHistory));

  return newScan;
}

export function clearScanHistory() {
  localStorage.removeItem(HISTORY_KEY);
}
