// Saboss: small progressive enhancements. Every page works without JavaScript.
"use strict";

// Ask before destructive actions: <form data-confirm="Delete this?">
document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

// Live scan progress: <div data-scan-status-url="/scans/1/status">
(function () {
  var box = document.querySelector("[data-scan-status-url]");
  if (!box) return;
  var url = box.getAttribute("data-scan-status-url");
  var label = box.querySelector("[data-status-label]");
  var started = Date.now();

  function poll() {
    fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (data && data.finished) {
          window.location.reload();
          return;
        }
        if (label && data) {
          var seconds = Math.round((Date.now() - started) / 1000);
          label.textContent = (data.status === "running" ? "Scanning" : "Waiting in queue") + " (" + seconds + "s)";
        }
        window.setTimeout(poll, 2000);
      })
      .catch(function () { window.setTimeout(poll, 5000); });
  }
  window.setTimeout(poll, 1500);
})();
