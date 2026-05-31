// CryptoKiddie ESIA (esia.gosuslugi.ru) UKEP login bridge.
//
// ESIA's electronic-signature login does NOT use the `gosuslugiPluginCrypto`
// postMessage API (that is the lk.gosuslugi.ru org-profile flow). It uses the
// `IFCPlugin` JavaScript client, which talks to a native plugin host THROUGH a
// browser extension using a window.postMessage transport:
//
//   page -> window.postMessage({type:"TO_IFC_EXT",  msg_data:<cmd>})
//   ext  -> window.postMessage({type:"FROM_IFC_EXT", msg_data:<resp>})
//
// where <cmd> = { func_name, params }. This file installs a transport-level
// interceptor: it answers the low-level func_name commands itself (routing
// certificate + signature work to the local CryptoKiddie bridge) so the page's
// own IFCPlugin instance keeps building IFCCertificate/IFCCrypto objects with
// its native logic. It also marks the extension/plugin as "installed/running"
// so ESIA enables the sign-in button.
(function () {
  "use strict";

  var BRIDGE_URL = window.__CRYPTOKIDDIE_ESIA_BRIDGE_URL || "http://127.0.0.1:18765";
  var FORCE_QUEUE = window.__CRYPTOKIDDIE_ESIA_FORCE_QUEUE !== false; // default ON (Safari/CSP)
  var KEY_ID = window.__CRYPTOKIDDIE_ESIA_KEY_ID || "03";
  var CRYPTO_ALIAS = "ruTokenECP";
  var CRYPTO_NUM = "0";
  var CRYPTO_ID = CRYPTO_ALIAS + "/" + CRYPTO_NUM; // matches IFCCrypto.getCryptoId() for pkcs11

  // ---- diagnostics ---------------------------------------------------------
  var log = (window.__ifcLog = window.__ifcLog || []);
  function rec(kind, data) {
    try {
      log.push({ t: Date.now(), kind: kind, data: data });
      if (log.length > 500) log.shift();
    } catch (_e) {}
  }

  // ---- bridge queue (fetch with external-pump fallback) --------------------
  var queue = (window.__cryptokiddieBridgeQueue = window.__cryptokiddieBridgeQueue || {
    requests: [],
    callbacks: {},
    nextId: 1
  });
  queue.requests = queue.requests || [];
  queue.callbacks = queue.callbacks || {};
  queue.nextId = queue.nextId || 1;

  window.__cryptokiddieBridgeDeliver = function (id, ok, payload) {
    var cb = queue.callbacks[id];
    if (!cb) return;
    delete queue.callbacks[id];
    if (ok) cb.resolve(payload);
    else cb.reject(new Error(payload && payload.error ? payload.error : String(payload)));
  };

  function queueJson(path, payload) {
    return new Promise(function (resolve, reject) {
      var id = String(queue.nextId++);
      queue.callbacks[id] = { resolve: resolve, reject: reject };
      queue.requests.push({ id: id, path: path, payload: payload || {} });
    });
  }

  function postJson(path, payload) {
    if (FORCE_QUEUE) return queueJson(path, payload);
    return fetch(BRIDGE_URL + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload || {})
    })
      .then(function (r) {
        if (!r.ok) throw new Error("bridge HTTP " + r.status);
        return r.json();
      })
      .catch(function () {
        return queueJson(path, payload);
      });
  }

  // ---- certificate caching -------------------------------------------------
  var certCache = null;

  // cert SIGNATURE alg OID -> public-key alg OID that IFCCertificate.getSignAlg expects
  var KEYALG_BY_SIGALG = {
    "1.2.643.7.1.1.3.2": "1.2.643.7.1.1.1.1", // GOST 2012-256
    "1.2.643.7.1.1.3.3": "1.2.643.7.1.1.1.2", // GOST 2012-512
    "1.2.643.2.2.3": "1.2.643.2.2.19" // GOST 2001
  };

  function toPluginDn(dn) {
    // bridge returns "OID=value;OID=value" (',' already substituted inside values)
    return String(dn || "").split(";").join("\n");
  }

  function isoDate(unixSecs) {
    try {
      return new Date(Number(unixSecs) * 1000).toUTCString();
    } catch (_e) {
      return "";
    }
  }

  function certEntryFromRecord(record) {
    var sigAlg = record.signatureAlgorithm || "";
    return {
      cert_sn: record.serialNumber || "",
      cert_subject: toPluginDn(record.subject),
      cert_issuer: toPluginDn(record.issuer),
      cert_valid_from: isoDate(record.notBefore),
      cert_valid_to: isoDate(record.notAfter),
      cert_sign_alg: KEYALG_BY_SIGALG[sigAlg] || sigAlg || "1.2.643.7.1.1.1.1",
      id: KEY_ID,
      base64: record.raw || "",
      pem: ""
    };
  }

  function loadCertEntry() {
    if (certCache) return Promise.resolve(certCache);
    return postJson("/certificates", {}).then(function (result) {
      var record = result && result.certificates && result.certificates[0];
      if (!record) throw new Error("bridge returned no certificate");
      certCache = certEntryFromRecord(record);
      certCache.__record = record;
      return certCache;
    });
  }

  function cryptoEntry() {
    return {
      type: "pkcs11",
      alias: CRYPTO_ALIAS,
      num: CRYPTO_NUM,
      name: "Rutoken ECP",
      model: "Rutoken ECP",
      path: "",
      description: "Rutoken ECP",
      serial_number: "",
      crypto_id: CRYPTO_ID,
      alg: ""
    };
  }

  // ---- signature mapping ---------------------------------------------------
  // IFCConst data/sign type ids (captured from page IFCConst)
  var DT_DATA = 1, DT_DATA_B64 = 2, DT_HASH = 3, DT_HASH_B64 = 4;
  var ST_SIMPLE = 1, ST_SIMPLE_REV = 2, ST_CMS_ATT = 3, ST_CMS_DET = 4,
    ST_CADES_ATT = 5, ST_CADES_DET = 6;

  function utf8Base64(str) {
    return btoa(unescape(encodeURIComponent(String(str))));
  }

  function isHexString(s) {
    s = String(s);
    return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
  }

  function hexToBase64(hex) {
    hex = String(hex);
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    var bin = "";
    for (var j = 0; j < bytes.length; j++) bin += String.fromCharCode(bytes[j]);
    return btoa(bin);
  }

  function signViaBridge(params) {
    var inType = Number(params.inDataType);
    var signType = Number(params.signType);
    var detached = signType === ST_CMS_DET || signType === ST_CADES_DET || signType === ST_SIMPLE;
    var cades = signType === ST_CADES_ATT || signType === ST_CADES_DET;

    var content, contentEncoding, contentFormat;
    if (inType === DT_DATA_B64) {
      content = params.data;
      contentEncoding = "base64";
      contentFormat = "data";
    } else if (inType === DT_HASH_B64) {
      content = params.data;
      contentEncoding = "base64";
      contentFormat = "hash";
    } else if (inType === DT_HASH) {
      content = utf8Base64(params.data);
      contentEncoding = "base64";
      contentFormat = "hash";
    } else {
      // DT_DATA (raw). The ESIA digital-login component passes the
      // digital_challenge HEX STRING directly as `data` to
      // signDataCmsAttached; a real plugin signs the literal bytes of that
      // string (its UTF-8/ASCII encoding), NOT the hex-decoded nonce.
      content = utf8Base64(params.data);
      contentEncoding = "base64";
      contentFormat = "data";
    }

    var envelope = {
      files: [{ content: content, contentEncoding: contentEncoding, contentFormat: contentFormat }],
      type: detached ? "detached" : "attached",
      signType: signType,
      inDataType: inType,
      cades: cades
    };
    rec("sign-request", { inDataType: inType, signType: signType, detached: detached, cades: cades, dataLen: (params.data || "").length });
    return postJson("/signature", envelope).then(function (result) {
      var cms = result && result.contents && result.contents[0];
      if (!cms) throw new Error("bridge returned no signature");
      return cms;
    });
  }

  // ---- low-level command handler (the IFCPlugin "transport") ---------------
  function ok(extra) {
    return Object.assign({ error_code: 0 }, extra || {});
  }
  function fail(code) {
    return { error_code: code == null ? -1 : code };
  }

  function handleCommand(cmd) {
    var fn = cmd && cmd.func_name;
    var params = (cmd && cmd.params) || {};
    rec("cmd", { func_name: fn, params: redact(params) });

    switch (fn) {
      case "version":
        return Promise.resolve(ok({ version: "2.2.1", plugin_version: "2.2.1" }));
      case "create":
        return Promise.resolve(ok({ real_id: params.containerId || "" }));
      case "get_guid":
        return Promise.resolve(ok({ guid: (params.prefix || "") + cryptoRandomGuid() }));

      case "get_list_info":
        return Promise.resolve(ok({ ifc_list: [cryptoEntry()] }));

      case "get_list_certs_by_cryptoid_array":
        return loadCertEntry().then(function (entry) {
          return ok({
            intermediate: false,
            result_array: [{ crypto_id: CRYPTO_ID, cert_list: [entry] }]
          });
        }).catch(function (e) { rec("err", String(e)); return fail(9); });

      case "get_list_certs":
        return loadCertEntry().then(function (entry) {
          return ok({ cert_list: [entry] });
        }).catch(function (e) { rec("err", String(e)); return fail(9); });

      case "get_list_keys":
        return loadCertEntry().then(function (entry) {
          return ok({ keys_list: [entry] });
        }).catch(function () { return ok({ keys_list: [] }); });

      case "load_x509_from_container":
      case "load_x509_from_data":
        return loadCertEntry().then(function (entry) {
          return ok({ x509Handle: 1, __entry: entry });
        }).catch(function (e) { rec("err", String(e)); return fail(9); });

      case "get_x509_info":
        return loadCertEntry().then(function (entry) {
          return ok({
            cert_info: {
              cert_sn: entry.cert_sn,
              cert_subject: entry.cert_subject,
              cert_issuer: entry.cert_issuer,
              cert_valid_from: entry.cert_valid_from,
              cert_valid_to: entry.cert_valid_to,
              cert_sign_alg: entry.cert_sign_alg,
              base64: entry.base64,
              pem: entry.pem,
              version: "3",
              extensions: ""
            }
          });
        }).catch(function (e) { rec("err", String(e)); return fail(9); });

      case "free_x509":
        return Promise.resolve(ok());

      case "sign":
        return signViaBridge(params).then(function (cms) {
          rec("sign-ok", { len: cms.length });
          // The ESIA digital-login component reads `fe.sign_value` from the
          // IFCPlugin sign response (then posts {signature: sign_value} to
          // /login/digital/validate). sign_value is the required field; the
          // rest are kept as harmless aliases for other consumers.
          return ok({
            sign_value: cms,
            sign: cms,
            signature: cms,
            sign_base64: cms,
            signature_base64: cms,
            result: cms,
            result_base64: cms,
            data: cms
          });
        }).catch(function (e) {
          rec("sign-err", String(e));
          return fail(-1);
        });

      case "hash":
        // bridge has no standalone hash endpoint; report unsupported so the
        // page falls back to hardware/internal hashing where possible.
        return Promise.resolve(fail(17));

      default:
        rec("unhandled", fn);
        return Promise.resolve(fail(17));
    }
  }

  function redact(params) {
    var p = {};
    for (var k in params) {
      if (k === "userPin") p[k] = "***";
      else if (k === "data" && params[k] && params[k].length > 64) p[k] = "[" + params[k].length + " chars]";
      else p[k] = params[k];
    }
    return p;
  }

  function cryptoRandomGuid() {
    var b = new Uint8Array(16);
    (window.crypto || {}).getRandomValues
      ? window.crypto.getRandomValues(b)
      : b.forEach(function (_, i) { b[i] = Math.floor(Math.random() * 256); });
    var h = [].map.call(b, function (x) { return ("0" + x.toString(16)).slice(-2); }).join("");
    return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
  }

  // ---- window transport: answer TO_IFC_EXT with FROM_IFC_EXT ---------------
  if (!window.__cryptokiddieIfcTransportInstalled) {
    window.__cryptokiddieIfcTransportInstalled = true;
    window.addEventListener("message", function (ev) {
      if (ev.source !== window) return;
      var msg;
      try {
        msg = typeof ev.data === "string" ? JSON.parse(ev.data) : ev.data;
      } catch (_e) {
        return;
      }
      if (!msg || msg.type !== "TO_IFC_EXT") return;
      Promise.resolve(handleCommand(msg.msg_data)).then(function (resp) {
        window.postMessage(JSON.stringify({ type: "FROM_IFC_EXT", msg_data: resp }), "*");
      });
    });
  }

  // ---- mark extension + native plugin as present ---------------------------
  function ensureMarker(id) {
    if (document.getElementById(id)) return;
    var el = document.createElement("div");
    el.id = id;
    el.style.display = "none";
    (document.body || document.documentElement).appendChild(el);
  }
  function installMarkers() {
    ensureMarker("ifcplugin-extension-is-installed");
    ensureMarker("ifc-plugin-is-installed");
  }
  installMarkers();
  // Re-assert markers + status periodically; ESIA polls every ~5s in init().
  var started = Date.now();
  var timer = window.setInterval(function () {
    installMarkers();
    try {
      var ev = document.createEvent("Event");
      ev.initEvent("updatePluginStatus", true, true);
      document.dispatchEvent(ev);
    } catch (_e) {}
    if (Date.now() - started > 120000) window.clearInterval(timer);
  }, 1000);

  // Pre-warm the certificate so cert-list commands resolve synchronously. The
  // IFCPlugin transport is single-slot (one outstanding request); a slow async
  // reply can be dropped, so we want the cert cached before ESIA enumerates.
  loadCertEntry()
    .then(function () { rec("cert-prewarmed", { cn: certCache && certCache.cert_subject.split("\n")[0] }); })
    .catch(function (e) { rec("cert-prewarm-err", String(e)); });

  rec("installed", { bridge: BRIDGE_URL, forceQueue: FORCE_QUEUE });
  console.info("CryptoKiddie ESIA IFCPlugin interceptor installed", BRIDGE_URL);
})();
