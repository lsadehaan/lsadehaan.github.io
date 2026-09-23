// Service worker for the Shop app: serves the app shell offline.
// Bump CACHE when shop assets change so installed apps pick up the update.
const CACHE = "shop-v1";
const SHELL = [
  "/shop/",
  "/shop/privacy/",
  "/assets/css/blog.css",
  "/assets/css/common.css",
  "/assets/css/emvtools.css",
  "/assets/css/shop.css",
  "/assets/js/shop.js",
  "/assets/js/categories.js",
  "/assets/shop/icon-192.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Network first so updates show up immediately; fall back to cache when offline.
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }))
  );
});
