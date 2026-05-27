(function () {
  const bridgeUrl = window.__CRYPTOKIDDIE_GOSUSLUGI_BRIDGE_URL || "http://127.0.0.1:18765";
  const bridgeQueue = window.__cryptokiddieBridgeQueue || { requests: [], callbacks: {}, nextId: 1 };
  bridgeQueue.requests = bridgeQueue.requests || [];
  bridgeQueue.callbacks = bridgeQueue.callbacks || {};
  bridgeQueue.nextId = bridgeQueue.nextId || 1;
  window.__cryptokiddieBridgeQueue = bridgeQueue;

  window.__cryptokiddieBridgeDeliver = function (id, ok, payload) {
    const callback = bridgeQueue.callbacks[id];
    if (!callback) return;
    delete bridgeQueue.callbacks[id];
    if (ok) {
      callback.resolve(payload);
    } else {
      callback.reject(new Error(payload && payload.error ? payload.error : String(payload)));
    }
  };

  function ensureMarker() {
    if (!document.querySelector('meta[property="gosuslugi.plugin.extension.content"]')) {
      const marker = document.createElement("meta");
      marker.setAttribute("property", "gosuslugi.plugin.extension.content");
      marker.setAttribute("content", "cryptokiddie");
      document.head.appendChild(marker);
    }
  }

  async function postJson(path, payload) {
    if (window.__CRYPTOKIDDIE_GOSUSLUGI_FORCE_QUEUE) {
      return queueJson(path, payload);
    }
    try {
      const response = await fetch(bridgeUrl + path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload || {})
      });
      if (!response.ok) {
        throw new Error("CryptoKiddie bridge HTTP " + response.status);
      }
      return response.json();
    } catch (_error) {
      return queueJson(path, payload);
    }
  }

  function queueJson(path, payload) {
    return new Promise((resolve, reject) => {
      const id = String(bridgeQueue.nextId++);
      bridgeQueue.callbacks[id] = { resolve, reject };
      bridgeQueue.requests.push({ id, path, payload: payload || {} });
    });
  }

  function pluginMessage(method, result) {
    return {
      node: "cryptokiddie",
      error: "",
      code: "200",
      method: {
        type: method,
        result: JSON.stringify(result)
      }
    };
  }

  function pluginError(method, error) {
    return {
      node: "cryptokiddie",
      error: String(error && error.message ? error.message : error),
      code: "20001",
      method: {
        type: method,
        result: ""
      }
    };
  }

  function replyToPostedMessage(source, original, response) {
    const message = Object.assign({}, original, response, {
      id: original.id,
      module: original.module,
      meta: original.meta
    });
    window.__cryptokiddiePostedReplies = window.__cryptokiddiePostedReplies || [];
    window.__cryptokiddiePostedReplies.push({
      id: message.id,
      method: message.method && message.method.type,
      resultLength: message.method && message.method.result ? message.method.result.length : 0,
      error: message.error || ""
    });
    source.postMessage(message, "*");
  }

  const partialCryptoPayloads = {};

  function parsePluginPayload(method, data, original, source) {
    if (!data) return { ready: true, payload: {}, original, source };
    const key = method;
    const text = String(data);
    if (!partialCryptoPayloads[key]) {
      try {
        return { ready: true, payload: JSON.parse(text), original, source };
      } catch (_error) {
        partialCryptoPayloads[key] = { text, original, source };
        return { ready: false };
      }
    }
    partialCryptoPayloads[key].text += text;
    try {
      const pending = partialCryptoPayloads[key];
      const payload = JSON.parse(pending.text);
      delete partialCryptoPayloads[key];
      return { ready: true, payload, original: pending.original, source: pending.source };
    } catch (_error) {
      return { ready: false };
    }
  }

  async function handleCryptoMessage(event) {
    const message = event.data;
    if (!message || message.node || !message.module || !message.method) return;
    if (message.module.type !== "crypto") return;

    const method = message.method.type;
    try {
      if (method === "certificates") {
        const parsed = parsePluginPayload(method, message.method.data, message, event.source || window);
        if (!parsed.ready) return;
        const payload = parsed.payload;
        const result = await postJson("/certificates", payload);
        replyToPostedMessage(parsed.source, parsed.original, pluginMessage(method, result.certificates));
      } else if (method === "signature" || method === "signatureV2") {
        const parsed = parsePluginPayload(method, message.method.data, message, event.source || window);
        if (!parsed.ready) return;
        const payload = parsed.payload;
        const result = await postJson("/signature", payload);
        replyToPostedMessage(parsed.source, parsed.original, pluginMessage(method, result.contents.map((content) => ({ content }))));
      } else if (method === "providers" || method === "tokens") {
        replyToPostedMessage(event.source || window, message, pluginMessage(method, []));
      }
    } catch (error) {
      replyToPostedMessage(event.source || window, message, pluginError(method, error));
    }
  }

  function installDirectFallback() {
    window.GosuslugiPluginFileInfo = window.GosuslugiPluginFileInfo || class GosuslugiPluginFileInfo {
      constructor(content, path, contentEncoding, id, name, contentFormat) {
        this.content = content;
        this.path = path;
        this.id = id || "";
        this.name = name || "";
        this.contentEncoding = contentEncoding || "";
        this.contentFormat = contentFormat || "";
      }
    };

    window.gosuslugiPluginCrypto = window.gosuslugiPluginCrypto || {
      certificates(request, callback) {
        postJson("/certificates", request)
          .then((result) => callback(pluginMessage("certificates", result.certificates)))
          .catch((error) => callback(pluginError("certificates", error)));
      },
      signature(request, callback) {
        postJson("/signature", request)
          .then((result) => callback(pluginMessage("signature", result.contents.map((content) => ({ content })))))
          .catch((error) => callback(pluginError("signature", error)));
      },
      signatureV2(request, callback) {
        this.signature(request, callback);
      },
      providers(_request, callback) {
        callback(pluginMessage("providers", []));
      },
      tokens(_request, callback) {
        callback(pluginMessage("tokens", []));
      }
    };
  }

  function keepDirectFallbackActive() {
    const started = Date.now();
    const timer = window.setInterval(() => {
      try {
        gosuslugiPluginCrypto = window.gosuslugiPluginCrypto;
      } catch (_error) {}
      if (Date.now() - started > 30000) {
        window.clearInterval(timer);
      }
    }, 250);
  }

  ensureMarker();
  installDirectFallback();
  keepDirectFallbackActive();
  window.addEventListener("message", handleCryptoMessage);
  console.info("CryptoKiddie Gosuslugi bridge injected", bridgeUrl);
})();