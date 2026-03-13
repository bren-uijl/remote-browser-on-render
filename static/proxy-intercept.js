/**
 * proxy-intercept.js  –  injected as first script in every proxied page.
 *
 * Patches fetch / XHR / src-writes / sendBeacon so that ALL runtime network
 * calls (lazy loaders, SPA routers, ad scripts, …) are routed through the
 * proxy instead of going directly to the original host.
 *
 * window.__PROXY_BASE__  –  absolute proxy origin, e.g. https://myproxy.onrender.com
 * window.__PAGE_URL__    –  the target URL that was fetched, e.g. https://topgear.com/
 *                           Used to resolve relative URLs that React/Next.js
 *                           writes at runtime (e.g. img.src = "/_next/…").
 */
(function (PROXY_BASE, PAGE_URL) {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────────────────────

  function b64encode(str) {
    // urlsafe base64, no padding  (matches Python's urlsafe_b64encode + rstrip '=')
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  var pageOrigin = '';
  try { pageOrigin = new URL(PAGE_URL).origin; } catch (_) {}

  function shouldProxy(url) {
    if (!url || typeof url !== 'string') return false;
    // Already going through the proxy
    if (url.indexOf(PROXY_BASE + '/fetch?') === 0) return false;
    if (url.indexOf('/fetch?') === 0) return false;
    // Safe schemes that never need proxying
    if (/^(data:|blob:|javascript:|mailto:|tel:|#)/.test(url)) return false;
    // Absolute external URL
    if (/^https?:\/\//.test(url)) return true;
    // Protocol-relative
    if (url.indexOf('//') === 0) return true;
    // Root-relative or path-relative — these resolve against the iframe's
    // origin (our proxy server), which is wrong. We must proxy them.
    if (url.indexOf('/') === 0 || url.indexOf('.') === 0) return true;
    return false;
  }

  function toAbsolute(url) {
    if (/^https?:\/\//.test(url)) return url;
    if (url.indexOf('//') === 0) return 'https:' + url;
    // Root-relative or path-relative: resolve against the original PAGE_URL
    try { return new URL(url, PAGE_URL).href; } catch (_) { return url; }
  }

  function proxyUrl(url) {
    var abs = toAbsolute(url);
    // Upgrade http → https to prevent mixed-content blocks
    abs = abs.replace(/^http:\/\//, 'https://');
    return PROXY_BASE + '/fetch?u=' + b64encode(abs);
  }

  // ── 1. window.fetch ───────────────────────────────────────────────────────

  var _origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    try {
      if (typeof input === 'string' && shouldProxy(input)) {
        input = proxyUrl(input);
      } else if (input && typeof input === 'object' && input.url && shouldProxy(input.url)) {
        input = new Request(proxyUrl(input.url), input);
      }
    } catch (_) {}
    return _origFetch(input, init);
  };

  // ── 2. XMLHttpRequest ─────────────────────────────────────────────────────

  var _origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    try {
      if (typeof url === 'string' && shouldProxy(url)) args[1] = proxyUrl(url);
    } catch (_) {}
    return _origOpen.apply(this, args);
  };

  // ── 3. Element.setAttribute ───────────────────────────────────────────────

  var _PROXIED_ATTRS = { src: 1, href: 1, action: 1, poster: 1,
                         'data-src': 1, 'data-lazy-src': 1, 'data-original': 1 };
  var _origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      if (_PROXIED_ATTRS[name.toLowerCase()] && typeof value === 'string' && shouldProxy(value)) {
        value = proxyUrl(value);
      }
    } catch (_) {}
    return _origSetAttr.call(this, name, value);
  };

  // ── 4. Direct .src / .href property writes ────────────────────────────────

  function trapProp(proto, prop) {
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.set) return;
    var origSet = desc.set;
    Object.defineProperty(proto, prop, {
      set: function (v) {
        try { if (typeof v === 'string' && shouldProxy(v)) v = proxyUrl(v); } catch (_) {}
        origSet.call(this, v);
      },
      get: desc.get,
      configurable: true,
      enumerable: desc.enumerable,
    });
  }

  [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement, HTMLSourceElement,
   HTMLVideoElement, HTMLAudioElement, HTMLTrackElement].forEach(function (C) {
    try { trapProp(C.prototype, 'src'); } catch (_) {}
  });
  try { trapProp(HTMLLinkElement.prototype, 'href'); } catch (_) {}

  // ── 5. navigator.sendBeacon ───────────────────────────────────────────────

  if (navigator.sendBeacon) {
    var _origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      try { if (shouldProxy(url)) url = proxyUrl(url); } catch (_) {}
      return _origBeacon(url, data);
    };
  }

  // ── 6. window.open ────────────────────────────────────────────────────────
  // Intercept popups so they open through the proxy too.

  var _origOpen2 = window.open;
  window.open = function (url, target, features) {
    try { if (url && shouldProxy(url)) url = proxyUrl(url); } catch (_) {}
    return _origOpen2.call(window, url, target, features);
  };

}(window.__PROXY_BASE__ || '', window.__PAGE_URL__ || ''));
