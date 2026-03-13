/**
 * proxy-intercept.js – injected as first script in every proxied page.
 *
 * Patches fetch / XHR / src-writes / sendBeacon so runtime network calls
 * (lazy loaders, SPA routers, ad scripts …) route through the proxy.
 *
 * window.__PROXY_BASE__  e.g. https://myproxy.onrender.com
 * window.__PAGE_URL__    e.g. https://topgear.com/  (the proxied target)
 */
(function (PROXY_BASE, PAGE_URL) {
  'use strict';

  var pageOrigin = '';
  try { pageOrigin = new URL(PAGE_URL).origin; } catch (_) {}

  // ── Helpers ───────────────────────────────────────────────────────────────

  function toAbsolute(url) {
    if (/^https?:\/\//.test(url)) return url;
    if (url.indexOf('//') === 0) return 'https:' + url;
    // Root-relative or path-relative → resolve against the *target page*,
    // NOT the proxy origin.  This is the key fix for the self-proxy loop.
    try { return new URL(url, PAGE_URL).href; } catch (_) { return url; }
  }

  function proxyUrl(url) {
    var abs = toAbsolute(url).replace(/^http:\/\//, 'https://');
    return PROXY_BASE + '/fetch?url=' + encodeURIComponent(abs);
  }

  function shouldProxy(url) {
    if (!url || typeof url !== 'string') return false;

    // ── Never proxy these ──────────────────────────────────────────────────
    // Already proxied
    if (url.indexOf(PROXY_BASE) === 0)        return false;
    if (url.indexOf('/fetch?url=') === 0)     return false;
    // Safe non-http schemes
    if (/^(data:|blob:|javascript:|mailto:|tel:|#)/.test(url)) return false;

    // ── Absolute URLs ──────────────────────────────────────────────────────
    if (/^https?:\/\//.test(url) || url.indexOf('//') === 0) {
      // If this URL points to our own proxy server, never proxy it
      // (e.g. /fetch?url=... or static assets served by Flask)
      var abs = toAbsolute(url);
      if (abs.indexOf(PROXY_BASE) === 0) return false;
      return true;
    }

    // ── Relative URLs (root-relative or path-relative) ─────────────────────
    // Resolve against PAGE_URL first, then check it's not our own server
    if (url.indexOf('/') === 0 || url.indexOf('.') === 0) {
      if (!PAGE_URL) return false;  // no page context – skip
      try {
        var resolved = new URL(url, PAGE_URL).href;
        if (resolved.indexOf(PROXY_BASE) === 0) return false;  // own server
        return true;
      } catch (_) { return false; }
    }

    return false;
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
  var _origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    try {
      if (typeof url === 'string' && shouldProxy(url)) args[1] = proxyUrl(url);
    } catch (_) {}
    return _origXHROpen.apply(this, args);
  };

  // ── 3. Element.setAttribute ───────────────────────────────────────────────
  var _PROXIED_ATTRS = {
    src: 1, href: 1, action: 1, poster: 1,
    'data-src': 1, 'data-lazy-src': 1, 'data-original': 1, 'data-bg': 1
  };
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

  [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement,
   HTMLSourceElement, HTMLVideoElement, HTMLAudioElement, HTMLTrackElement
  ].forEach(function (C) { try { trapProp(C.prototype, 'src'); } catch (_) {} });
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
  var _origWindowOpen = window.open;
  window.open = function (url, target, features) {
    try { if (url && shouldProxy(url)) url = proxyUrl(url); } catch (_) {}
    return _origWindowOpen.call(window, url, target, features);
  };

}(window.__PROXY_BASE__ || '', window.__PAGE_URL__ || ''));
