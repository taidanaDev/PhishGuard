const API_BASE_URLS = ["http://127.0.0.1:8000", "http://127.0.0.1:8001"];

export async function scanUrl(url) {
  let lastError;

  for (const apiBaseUrl of API_BASE_URLS) {
    try {
      const response = await fetch(`${apiBaseUrl}/predict`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error("Failed to scan URL.");
      }

      return await response.json();
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("Backend is not running.");
}
