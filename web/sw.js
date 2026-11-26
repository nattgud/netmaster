// Service worker: caches the app shell so the PWA starts even when the backend is down.
const CACHE = 'netmaster-v4';
const SHELL = ['./', 'index.html', 'style.css', 'app.js', 'i18n.js', 'i18n/strings.tsv', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api') || url.pathname === '/ws') return;
  // Network first, cache as fallback, so updates show up right away.
  e.respondWith(
    fetch(e.request.mode === 'navigate' ? e.request.url : e.request, { cache: 'no-cache' })
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request)),
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = new URL(e.notification.data?.url || './', self.registration.scope).href;
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const win = list.find((c) => 'focus' in c);
      if (win) { win.navigate?.(url); return win.focus(); }
      return self.clients.openWindow(url);
    }),
  );
});

// Web Push: alerts from the server even when the app is closed.
self.addEventListener('push', (e) => {
  let data = { title: 'NetMaster', body: '' };
  try { data = e.data ? e.data.json() : data; } catch { data.body = e.data?.text() || ''; }
  e.waitUntil(self.registration.showNotification(data.title, {
    body: data.body || '',
    tag: data.tag,
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
    requireInteraction: data.severity === 'critical',
    data: { url: data.url || './' },
  }));
});
