function About() {
  return (
    <main className="app">
      <section className="page-header">
        <p className="tag">ABOUT PHISHGUARD</p>
        <h1>AI-powered phishing URL detection.</h1>
        <p className="subtitle">
          PhishGuard is a Progressive Web App designed to help users check suspicious URLs using machine learning.
        </p>
      </section>

      <section className="about-layout">
        <article className="about-card">
          <h2>Project Purpose</h2>
          <p>
            Many users receive suspicious links through messages, emails, and social platforms.
            PhishGuard helps users analyze a URL before opening it by detecting possible phishing patterns.
          </p>
        </article>

        <article className="about-card">
          <h2>AI Approach</h2>
          <p>
            The system uses machine learning to classify URLs as legitimate or phishing.
            The backend analyzes URL-based patterns and returns a prediction, confidence score, risk level, and detected URL features.
          </p>
        </article>

        <article className="about-card">
          <h2>PWA Features</h2>
          <p>
            PhishGuard is designed as a responsive web app for desktop and mobile use.
            It includes scan history, dashboard statistics, and app-like navigation.
          </p>
        </article>

        <article className="about-card warning-card">
          <h2>Important Limitation</h2>
          <p>
            PhishGuard does not guarantee complete safety. It provides a prediction based on the trained model and URL patterns.
            Users should still verify websites before entering sensitive information.
          </p>
        </article>
      </section>
    </main>
  );
}

export default About;