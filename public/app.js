(function () {
  "use strict";

  var btn = document.getElementById("logout-btn");
  if (!btn) return;

  var busy = false;

  btn.addEventListener("click", function () {
    if (busy) return;
    var ok = window.confirm("Log out of SOMN Studio?");
    if (!ok) return;

    busy = true;
    fetch("/api/logout", { method: "POST", credentials: "same-origin" })
      .then(function () {
        window.location.href = "/login";
      })
      .catch(function () {
        // Even if the request fails, send the user to the login screen —
        // the cookie is short-lived and this keeps the UI from feeling stuck.
        window.location.href = "/login";
      });
  });
})();
