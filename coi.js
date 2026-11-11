// Cross-origin isolation on a static host that cannot set response headers (GitHub Pages).
// Wasm threads need SharedArrayBuffer, which browsers withhold unless the page is served with
// COOP/COEP. In the page, this script registers itself as a service worker and reloads once the
// worker controls the page; as the worker, it adds the headers to every response in its scope.
// Where the headers are already sent (serve.mjs), the page is isolated and this does nothing.
if (typeof window === 'undefined') {
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
  self.addEventListener('fetch', event => {
    const { request } = event;
    // A request the worker may not re-issue (devtools' cache probes): leave it to the browser.
    if (request.cache === 'only-if-cached' && request.mode !== 'same-origin') return;
    event.respondWith(
      fetch(request).then(response => {
        if (response.status === 0) return response; // opaque: its headers cannot be changed
        const headers = new Headers(response.headers);
        headers.set('Cross-Origin-Opener-Policy', 'same-origin');
        headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
        headers.set('Cross-Origin-Resource-Policy', 'same-origin');
        return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
      }),
    );
  });
} else if (crossOriginIsolated) {
  sessionStorage.removeItem('coi-reloaded');
} else if (isSecureContext && navigator.serviceWorker) {
  // Reload at most once per tab: if the page is still not isolated after that, the browser is
  // refusing (a private window without service workers, say) and the page says so itself.
  const reloaded = sessionStorage.getItem('coi-reloaded');
  navigator.serviceWorker.register(document.currentScript.src).then(registration => {
    if (reloaded) return;
    const reload = () => {
      sessionStorage.setItem('coi-reloaded', '1');
      location.reload();
    };
    // First visit: the worker claims the page once it activates. A hard reload bypasses an
    // active worker, and a plain reload puts the page back under it.
    navigator.serviceWorker.addEventListener('controllerchange', reload);
    if (registration.active && !navigator.serviceWorker.controller) reload();
  });
}
