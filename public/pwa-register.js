// Service worker is intentionally network-only; no sensitive data is stored offline.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .catch(() => { /* Website remains usable if registration is disallowed. */ });
  });
}
