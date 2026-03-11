/**
 * proxy-intercept.js
 * Injected into every proxied HTML page.
 * Intercepts all runtime network requests and routes them through the proxy.
 */
(function (PROXY_BASE) {
  'use strict';

  function shouldProxy(url) {
    if (!url) return false;
    try {
      // Already going through our proxy
      if (url.startsWith(PROXY_BASE + '/fetch?url=') || url.startsWith('/fetch?url=')) return false;
      // Relative paths, data URIs, blob URLs, fragment-only
      if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('#')) return false;
      // Absolute URL pointing somewhere other than our proxy — rewrite it
      if (url.startsWith('http://') || url.startsWith('https://')) return true;
      // Protocol-relative
      if (url.startsWith('//')) return true;
      // Relative URL — let the browser handle it normally (base tag is gone,
      // so the browser resolves it against our proxy origin which is correct)
      return false;
    } catch (_) { return false; }
  }

  function proxyUrl(url) {
    if (url.startsWith('//')) url = 'https:' + url;
    // Upgrade http to https to avoid mixed-content
    if (url.startsWith('http://')) url = 'https://' + url.slice(7);
    return PROXY_BASE + '/fetch?url=' + encodeURIComponent(url);
  }

  // ── 1. Override window.fetch ───────────────────────────────────────────────
  const _origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    if (typeof input === 'string' && shouldProxy(input)) {
      input = proxyUrl(input);
    } else if (input instanceof Request && shouldProxy(input.url)) {
      input = new Request(proxyUrl(input.url), input);
    }
    return _origFetch(input, init);
  };

  // ── 2. Override XMLHttpRequest ─────────────────────────────────────────────
  const _origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    if (typeof url === 'string' && shouldProxy(url)) {
      url = proxyUrl(url);
    }
    return _origOpen.call(this, method, url, ...rest);
  };

  // ── 3. Intercept dynamic src / href writes via MutationObserver ────────────
  // Covers: JS that does  img.src = '...'  or  el.setAttribute('src', '...')
  const _origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const tag = this.tagName ? this.tagName.toLowerCase() : '';
    const attr = name.toLowerCase();
    if (typeof value === 'string' && shouldProxy(value)) {
      if (
        (attr === 'src'  && ['img','script','iframe','source','input'].includes(tag)) ||
        (attr === 'href' && ['link','a'].includes(tag)) ||
        attr === 'action' ||
        attr === 'data-src' || attr === 'data-lazy-src'
      ) {
        value = proxyUrl(value);
      }
    }
    return _origSetAttr.call(this, name, value);
  };

  // Also trap direct .src property writes
  function trapSrc(proto) {
    const desc = Object.getOwnPropertyDescriptor(proto, 'src');
    if (!desc || !desc.set) return;
    const origSet = desc.set;
    Object.defineProperty(proto, 'src', {
      set(v) {
        if (typeof v === 'string' && shouldProxy(v)) v = proxyUrl(v);
        origSet.call(this, v);
      },
      get: desc.get,
      configurable: true,
    });
  }
  [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement, HTMLSourceElement]
    .forEach(c => { try { trapSrc(c.prototype); } catch (_) {} });

  // ── 4. Intercept navigator.sendBeacon ─────────────────────────────────────
  if (navigator.sendBeacon) {
    const _origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      if (shouldProxy(url)) url = proxyUrl(url);
      return _origBeacon(url, data);
    };
  }

}(window.__PROXY_BASE__ || ''));
