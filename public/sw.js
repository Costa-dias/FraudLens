// Installability lifecycle only: never cache app data, API responses, passwords or tokens.
self.addEventListener('install', () => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });
// Network remains authoritative. No fetch interception or personal-data caching.
