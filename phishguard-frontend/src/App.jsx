import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Home from "./pages/Home";
import Scan from "./pages/Scan";
import History from "./pages/History";
import Dashboard from "./pages/Dashboard";
import SafetyTips from "./pages/SafetyTips";
import About from "./pages/About";
import logoImage from "./assets/phishguard-logo.webp";
import "./App.css";

function App() {
  return (
    <BrowserRouter>
      <nav className="navbar">
        <div className="brand">
          <img className="brand-mark" src={logoImage} alt="PhishGuard logo" />
          <h2 className="logo">PHISHGUARD</h2>
        </div>

        <div className="nav-links">
          <NavLink to="/">Home</NavLink>
          <NavLink to="/scan">Scan</NavLink>
          <NavLink to="/history">History</NavLink>
          <NavLink to="/dashboard">Dashboard</NavLink>
          <NavLink to="/tips">Safety Tips</NavLink>
          <NavLink to="/about">About</NavLink>
        </div>
      </nav>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/history" element={<History />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/tips" element={<SafetyTips />} />
        <Route path="/about" element={<About />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
