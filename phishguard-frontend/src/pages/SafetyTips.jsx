function SafetyTips() {
  const tips = [
    {
      title: "Check the domain carefully",
      description:
        "Phishing links often imitate real websites using misspelled domains, extra words, or unusual subdomains.",
    },
    {
      title: "Be careful with login links",
      description:
        "Avoid entering passwords after clicking links from messages, emails, or unknown senders.",
    },
    {
      title: "Look for suspicious keywords",
      description:
        "Words like verify, update, free, account, secure, banking, and password may appear in phishing URLs.",
    },
    {
      title: "Do not trust HTTPS alone",
      description:
        "HTTPS means the connection is encrypted, but it does not always mean the website is legitimate.",
    },
    {
      title: "Avoid shortened links from unknown sources",
      description:
        "Shortened URLs can hide the real destination and are commonly used to disguise suspicious websites.",
    },
    {
      title: "Verify before clicking",
      description:
        "When unsure, go directly to the official website instead of clicking the link you received.",
    },
  ];

  return (
    <main className="app">
      <section className="page-header">
        <p className="tag">SAFETY TIPS</p>
        <h1>How to Avoid Phishing Links</h1>
        <p className="subtitle">
          Learn basic signs of phishing URLs before opening suspicious links.
        </p>
      </section>

      <section className="tips-grid">
        {tips.map((tip, index) => (
          <article className="tip-card" key={index}>
            <span className="tip-number">0{index + 1}</span>
            <h2>{tip.title}</h2>
            <p>{tip.description}</p>
          </article>
        ))}
      </section>
    </main>
  );
}

export default SafetyTips;