(function () {
  "use strict";

  var form = document.getElementById("login-form");
  var pwInput = document.getElementById("password");
  var errorBox = document.getElementById("login-error");
  var submitBtn = document.getElementById("login-submit");
  var submitLabel = document.getElementById("login-submit-label");
  var toggleBtn = document.getElementById("toggle-password");
  var toggleIcon = toggleBtn ? toggleBtn.querySelector("span") : null;

  if (!form || !pwInput || !errorBox || !submitBtn || !submitLabel) return;

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
  }

  function hideError() {
    errorBox.classList.add("hidden");
    errorBox.textContent = "";
  }

  function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    submitLabel.textContent = isLoading ? "Checking\u2026" : "Enter Studio";
  }

  function safeNextPath() {
    try {
      var params = new URLSearchParams(window.location.search);
      var next = params.get("next");
      if (next && next.indexOf("/") === 0 && next.indexOf("//") !== 0) {
        return next;
      }
    } catch (e) {
      /* ignore */
    }
    return "/overview";
  }

  if (toggleBtn && toggleIcon) {
    toggleBtn.addEventListener("click", function () {
      var showing = pwInput.type === "text";
      pwInput.type = showing ? "password" : "text";
      toggleIcon.textContent = showing ? "visibility" : "visibility_off";
      pwInput.focus();
    });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    hideError();

    var password = pwInput.value;
    if (!password) {
      showError("Enter the studio password.");
      pwInput.focus();
      return;
    }

    setLoading(true);

    fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password }),
      credentials: "same-origin",
    })
      .then(function (res) {
        return res
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            return { status: res.status, data: data };
          });
      })
      .then(function (result) {
        setLoading(false);
        if (result.status === 200 && result.data && result.data.ok) {
          window.location.href = safeNextPath();
          return;
        }
        if (result.status === 429) {
          showError(
            (result.data && result.data.error) ||
              "Too many attempts. Please wait a few minutes and try again."
          );
          return;
        }
        showError((result.data && result.data.error) || "Incorrect password.");
        pwInput.value = "";
        pwInput.focus();
      })
      .catch(function () {
        setLoading(false);
        showError("Network error \u2014 please check your connection and try again.");
      });
  });
})();
