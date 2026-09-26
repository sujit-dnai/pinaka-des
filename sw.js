self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{ e.respondWith(fetch(e.request).then(r=>{ const c=r.clone(); caches.open('pinaka-demo').then(k=>k.put(e.request,c)).catch(()=>{}); return r; }).catch(()=>caches.match(e.request))); });
