/**
 * Peek target-frame wrapper.
 *
 * The host page must never be the target page's direct parent. This
 * extension-origin document stays between the two, so every HTTP(S) target is
 * cross-origin from its parent while requests retain the extension context
 * needed for authenticated cookies on hosts the extension may access.
 *
 * It also relays the existing host ↔ child bridge without interpreting it.
 */
(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const raw = params.get("url");
  const token = params.get("token") || "";
  let url = null;
  try {
    url = new URL(raw || "");
  } catch {}
  if (!url || !/^https?:$/.test(url.protocol) || !token) return;

  // A secure host cannot frame an insecure redirect. Apply the upgrade only
  // for that case; an ordinary HTTP host must keep HTTP-only targets working.
  if (params.get("upgrade") === "1") {
    const policy = document.createElement("meta");
    policy.httpEquiv = "Content-Security-Policy";
    policy.content = "upgrade-insecure-requests";
    document.head.append(policy);
  }

  const frame = document.createElement("iframe");
  frame.setAttribute("allow", "clipboard-write; fullscreen; picture-in-picture");
  frame.setAttribute("referrerpolicy", "no-referrer");

  window.addEventListener("message", (event) => {
    const data = event.data;
    if (event.source === window.parent) {
      if (data?.__peek === "cmd") frame.contentWindow?.postMessage(data, "*");
      return;
    }
    if (event.source === frame.contentWindow && data?.__peek === "child") {
      window.parent.postMessage(data, "*");
    }
  });

  frame.addEventListener("load", () => {
    window.parent.postMessage({ __peekFrame: "load", token }, "*");
  });

  // Set the final, always cross-origin URL before connecting the frame. The
  // extension-initiator DNR rule is already live, so framing headers cannot
  // win a race.
  frame.src = url.href;
  document.body.append(frame);
})();
