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
    source.postMessage(message, "*");
  }

  async function handleCryptoMessage(event) {
    const message = event.data;
    if (!message || message.node || !message.module || !message.method) return;
    if (message.module.type !== "crypto") return;

    const method = message.method.type;
    try {
      if (method === "certificates") {
        const payload = message.method.data ? JSON.parse(message.method.data) : {};
        const result = await postJson("/certificates", payload);
        replyToPostedMessage(event.source || window, message, pluginMessage(method, result.certificates));
      } else if (method === "signature" || method === "signatureV2") {
        const payload = message.method.data ? JSON.parse(message.method.data) : {};
        const result = await postJson("/signature", payload);
        replyToPostedMessage(event.source || window, message, pluginMessage(method, result.contents.map((content) => ({ content }))));
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

  ensureMarker();
  installDirectFallback();
  window.addEventListener("message", handleCryptoMessage);
  console.info("CryptoKiddie Gosuslugi bridge injected", bridgeUrl);
})();