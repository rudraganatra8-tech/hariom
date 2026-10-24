// Hari Om service worker: opens the app instantly, works offline, and shows your reminder notifications.
const CACHE = 'hariom-v2';
const SHELL = ['/', '/index.html', '/styles.css', '/app.js', '/theme.js', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

// Data calls are never cached. Everything else: network first, cache when offline.
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then((r) => r || caches.match('/index.html')))
  );
});

// The push message itself carries no text. We fetch the text from your own server (logged in via your private cookie).
self.addEventListener('push', (e) => {
  e.waitUntil(
    (async () => {
      let items = [];
      try {
        const r = await fetch('/api/notifs', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hariom' },
          body: '{}',
        });
        if (r.ok) items = (await r.json()).items || [];
      } catch {}
      if (!items.length) items = [{ id: 'hariom', title: 'Hari Om', body: 'You have a reminder. Open the app to see it.', url: '/?tab=rem' }];
      for (const n of items) {
        await self.registration.showNotification(n.title || 'Hari Om', {
          body: n.body || '',
          icon: '/icons/icon-192.png',
          badge: '/icons/icon-192.png',
          tag: n.id || 'hariom',
          data: { url: n.url || '/' },
          vibrate: [60, 40, 60],
        });
      }
    })()
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = new URL((e.notification.data && e.notification.data.url) || '/', location.origin).href;
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.startsWith(location.origin) && 'focus' in c) {
          c.navigate(target).catch(() => {});
          return c.focus();
        }
      }
      return self.clients.openWindow(target);
    })
  );
});
