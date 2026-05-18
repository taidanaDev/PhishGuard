import logoImage from "../assets/phishguard-logo.webp";

function Home() {
  return (
    <main className="app">
      <section className="hero">
        <div className="hero-copy">
          <p className="tag">PHISHGUARD SYSTEM</p>
          <h1>Pixel-powered phishing URL detection.</h1>
          <p className="subtitle">
            Paste suspicious links and let PhishGuard check for phishing patterns before you open them.
          </p>
          <a className="start-button" href="/scan">
            Start Scanning
          </a>
        </div>

        <div className="hero-panel" aria-hidden="true">
          <img className="hero-logo" src={logoImage} alt="" />
        </div>
      </section>
    </main>
  );
}

export default Home;
