# 🛡️ PhishGuard — Backend API

Phishing URL detector powered by Machine Learning.
Trained on **235,795 URLs** from the PhiUSIIL Phishing URL Dataset.

| Metric    | Score   |
|-----------|---------|
| Accuracy  | 99.80%  |
| Precision | 99.66%  |
| Recall    | 99.99%  |
| F1 Score  | 99.82%  |

---

## 🚀 How to Run (For Groupmates)

### Step 1 — Install Python
Download and install Python from 👉 [python.org/downloads](https://python.org/downloads)

> ⚠️ During installation, make sure to check ✅ **"Add Python to PATH"** before clicking Install!

---

### Step 2 — Download this project
Click the green **Code** button on this page → **Download ZIP**

Then right-click the ZIP file → **Extract All**

---

### Step 3 — Open terminal inside the folder

1. Open the extracted `phishguard-backend` folder
2. Click on the **address bar** at the top of the folder window
3. Type `cmd` and press **Enter** — this opens terminal directly inside the folder

---

### Step 4 — Install the required libraries

```
pip install -r requirements.txt
```

Wait for everything to finish downloading.

---

### Step 5 — Start the server

```
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

✅ The backend is now running!

> ⚠️ Keep this terminal window open. Closing it stops the server.

---

### Step 6 — Test it in your browser

Open your browser and go to:
```
http://localhost:8000/docs
```

You'll see an interactive page where you can test the API by typing in URLs.

---

## 📡 API Endpoints

| Method | URL | What it does |
|--------|-----|--------------|
| GET | `/` | Check if server is running |
| GET | `/health` | Server health status |
| GET | `/model/info` | ML model details and accuracy |
| POST | `/predict` | Check a single URL |
| POST | `/predict/bulk` | Check up to 50 URLs at once |

---

## 📬 For the Frontend Groupmate

Base URL while running locally:
```
http://localhost:8000
```

### Check a single URL:
```javascript
const response = await fetch("http://localhost:8000/predict", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: "https://example.com" })
});

const data = await response.json();

console.log(data.prediction);   // "legitimate" or "phishing"
console.log(data.is_phishing);  // true or false
console.log(data.risk_level);   // "safe", "low", "medium", or "high"
console.log(data.confidence);   // { phishing: 0.99, legitimate: 0.01 }
```

### Example response:
```json
{
  "url": "http://paypal-secure-verify.xyz/login",
  "prediction": "phishing",
  "is_phishing": true,
  "risk_level": "high",
  "confidence": {
    "phishing": 0.9998,
    "legitimate": 0.0002
  },
  "url_features": {
    "domain": "paypal-secure-verify.xyz",
    "tld": "xyz",
    "has_https": false,
    "suspicious_flags": [
      "Not using HTTPS",
      "Suspicious TLD (.xyz)",
      "Contains sensitive keywords"
    ]
  }
}
```

### Risk levels explained:
| Risk Level | Meaning |
|------------|---------|
| `safe` | Very likely legitimate |
| `low` | Probably fine, minor concerns |
| `medium` | Suspicious, use caution |
| `high` | Very likely phishing ⚠️ |

---

## 📁 Project Structure

```
phishguard-backend/
├── app/
│   ├── main.py          ← The API code
│   ├── model.pkl        ← Trained ML model
│   └── metrics.json     ← Model performance data
├── requirements.txt     ← Libraries needed
└── README.md            ← This file
```

---

## ❓ Common Problems

**"uvicorn is not recognized"**
→ Use `python -m uvicorn ...` instead of just `uvicorn ...`

**"No such file or directory: requirements.txt"**
→ Make sure your terminal is inside the `phishguard-backend` folder. Use the `cmd` trick in Step 3.

**"python is not recognized"**
→ Python wasn't added to PATH. Reinstall Python and check ✅ "Add Python to PATH" during install.
