/**
 * proxy-intercept.js  v1.0.8
 *
 * Injected as the FIRST script in every proxied page.
 * Routes ALL runtime network calls through the proxy.
 *
 * window.__PROXY_BASE__  = "https://myproxy.onrender.com"   (no trailing slash)
 * window.__PAGE_URL__    = "https://targetsite.com/path"    (the proxied URL)
 */
(function (PROXY_BASE, PAGE_URL) {
  'use strict';

  if (!PROXY_BASE) return; // safety: don't run if not injected properly

  /* ── helpers ──────────────────────────────────────────────────────────── */

  /**
   * Resolve any URL string to an absolute https:// URL.
   * Uses PAGE_URL as the base for relative paths.
   */
  function toAbsolute(url) {
    if (!url || typeof url !== 'string') return '';
    // Already absolute
    if (/^https?:\/\//.test(url)) return url.replace(/^http:\/\//, 'https://');
    // Protocol-relative
    if (url.slice(0, 2) === '//') return 'https:' + url;
    // Relative (root-relative or path-relative) – resolve against the target page
    try { return new URL(url, PAGE_URL).href.replace(/^http:\/\//, 'https://'); }
    catch (_) { return url; }
  }

  /**
   * Return the full /fetch?url=... proxy URL.
   */
  function proxyUrl(url) {
    return PROXY_BASE + '/fetch?url=' + encodeURIComponent(toAbsolute(url));
  }

  /**
   * Decide whether a URL needs to be proxied.
   * Key invariant: if the resolved absolute URL starts with PROXY_BASE
   * it is ALREADY on our server → never proxy it again.
   */
  function needsProxy(url) {
    if (!url || typeof url !== 'string') return false;
    // Safe schemes – never touch
    if (/^(data:|blob:|javascript:|mailto:|tel:|#|about:)/.test(url)) return false;
    // Resolve to absolute first so we can do a clean domain check
    var abs = toAbsolute(url);
    if (!abs) return false;
    // Already points to our proxy server (static files, /fetch routes, etc.)
    if (abs.slice(0, PROXY_BASE.length) === PROXY_BASE) return false;
    // Already going through the proxy (shouldn't normally happen but be safe)
    if (abs.indexOf('/fetch?url=') !== -1) return false;
    // Everything else that resolved to an http(s) URL needs proxying
    return /^https:\/\//.test(abs);
  }

  /* ── 1. fetch() ───────────────────────────────────────────────────────── */
  var _fetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    try {
      var url = typeof input === 'string' ? input
              : (input && input.url) ? input.url : null;
      if (url && needsProxy(url)) {
        var px = proxyUrl(url);
        input = typeof input === 'string' ? px : new Request(px, input);
      }
    } catch (_) {}
    return _fetch(input, init);
  };

  /* ── 2. XMLHttpRequest ────────────────────────────────────────────────── */
  var _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function () {
    var args = Array.prototype.slice.call(arguments);
    try {
      if (typeof args[1] === 'string' && needsProxy(args[1]))
        args[1] = proxyUrl(args[1]);
    } catch (_) {}
    return _xhrOpen.apply(this, args);
  };

  /* ── 3. Element.setAttribute ─────────────────────────────────────────── */
  var _ATTR = { src:1, href:1, action:1, poster:1,
                'data-src':1, 'data-lazy-src':1, 'data-original':1,
                'data-bg':1, 'data-url':1 };
  var _setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, val) {
    try {
      if (typeof val === 'string' && _ATTR[name.toLowerCase()] && needsProxy(val))
        val = proxyUrl(val);
    } catch (_) {}
    return _setAttr.call(this, name, val);
  };

  /* ── 4. Direct property writes (.src, .href) ─────────────────────────── */
  function trap(Cls, prop) {
    if (!Cls || !Cls.prototype) return;
    var d = Object.getOwnPropertyDescriptor(Cls.prototype, prop);
    if (!d || !d.set) return;
    var orig = d.set;
    Object.defineProperty(Cls.prototype, prop, {
      configurable: true, enumerable: d.enumerable,
      get: d.get,
      set: function (v) {
        try { if (typeof v === 'string' && needsProxy(v)) v = proxyUrl(v); }
        catch (_) {}
        orig.call(this, v);
      }
    });
  }
  [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement,
   HTMLSourceElement, HTMLVideoElement, HTMLAudioElement, HTMLTrackElement
  ].forEach(function (C) { trap(C, 'src'); });
  trap(HTMLLinkElement, 'href');

  /* ── 5. sendBeacon ───────────────────────────────────────────────────── */
  if (navigator.sendBeacon) {
    var _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      try { if (needsProxy(url)) url = proxyUrl(url); } catch (_) {}
      return _beacon(url, data);
    };
  }

  /* ── 6. window.open ──────────────────────────────────────────────────── */
  var _open = window.open;
  window.open = function (url, target, feat) {
    try { if (url && needsProxy(url)) url = proxyUrl(url); } catch (_) {}
    return _open.call(window, url, target, feat);
  };

  /* ── 7. history.pushState / replaceState ─────────────────────────────── */
  // When an SPA navigates, update __PAGE_URL__ so relative URLs keep resolving
  // correctly (especially important for Next.js client-side routing).
  function wrapHistory(method) {
    var orig = history[method];
    history[method] = function (state, title, url) {
      if (url) {
        try { PAGE_URL = toAbsolute(url); } catch (_) {}
      }
      return orig.apply(history, arguments);
    };
  }
  try { wrapHistory('pushState'); wrapHistory('replaceState'); } catch (_) {}

}(window.__PROXY_BASE__ || '', window.__PAGE_URL__ || ''));
