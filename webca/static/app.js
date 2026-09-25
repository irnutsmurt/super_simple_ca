/* SuperSimpleCA — progress feedback, submit spinners, notification bell. */
(function () {
  "use strict";

  // ---------------------------------------------------------- progress bar
  var bar = document.getElementById("progress-bar");
  var barTimer = null;
  function startProgress() {
    if (!bar) return;
    bar.classList.add("active");
    bar.style.width = "0%";
    // Force reflow so the transition runs from 0.
    void bar.offsetWidth;
    var pct = 8;
    bar.style.width = pct + "%";
    clearInterval(barTimer);
    barTimer = setInterval(function () {
      pct += (90 - pct) * 0.12;          // ease toward 90% but never finish
      bar.style.width = pct.toFixed(1) + "%";
    }, 200);
  }
  function finishProgress() {
    if (!bar) return;
    clearInterval(barTimer);
    bar.style.width = "100%";
    setTimeout(function () {
      bar.classList.remove("active");
      bar.style.width = "0%";
    }, 250);
  }
  // A normal navigation ends by unloading the page; show the bar until then.
  window.addEventListener("pageshow", finishProgress);

  // ---------------------------------------------------- form submit spinners
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form.getAttribute("data-no-progress") !== null) return;
    startProgress();
    var btn = form.querySelector('button:not([type="button"]), input[type="submit"]');
    if (btn && !btn.classList.contains("linkbtn")) {
      btn.classList.add("loading");
      btn.disabled = true;
      // Re-enable if the browser restores the page from bfcache (back button).
      window.addEventListener("pageshow", function () {
        btn.classList.remove("loading");
        btn.disabled = false;
      });
    }
  }, true);

  // --------------------------------------------------- link navigation bar
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("a");
    if (!a) return;
    var href = a.getAttribute("href") || "";
    if (a.target === "_blank" || a.hasAttribute("download")) return;
    if (href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("javascript:")) return;
    if (a.classList.contains("notif-item")) { /* still navigate, show bar */ }
    if (a.origin && a.origin !== window.location.origin) return;
    startProgress();
  });

  // ---------------------------------------------------------- bell dropdown
  var bellBtn = document.getElementById("bell-btn");
  var dropdown = document.getElementById("notif-dropdown");
  if (bellBtn && dropdown) {
    bellBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      dropdown.hidden = !dropdown.hidden;
    });
    document.addEventListener("click", function (e) {
      if (!dropdown.hidden && !dropdown.contains(e.target) && e.target !== bellBtn) {
        dropdown.hidden = true;
      }
    });
  }

  // ------------------------------------------------------- copy to clipboard
  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-copy],[data-copy-text]");
    if (!btn) return;
    e.preventDefault();
    var text = btn.getAttribute("data-copy-text");
    if (!text) {
      var sel = btn.getAttribute("data-copy");
      var el = sel && document.querySelector(sel);
      text = el ? (el.innerText || el.textContent) : "";
    }
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "copied ✓";
      setTimeout(function () { btn.textContent = old; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () {});
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (err) {}
      document.body.removeChild(ta);
    }
  });

  // ------------------------------------------------------ flash auto-dismiss
  document.querySelectorAll(".flash.flash-ok").forEach(function (f) {
    setTimeout(function () {
      f.style.transition = "opacity .5s, margin .5s, height .5s";
      f.style.opacity = "0";
      setTimeout(function () { f.style.display = "none"; }, 500);
    }, 5000);
  });

  // ------------------------------------------------ live unread badge poll
  var badge = document.getElementById("bell-badge");
  if (badge) {
    setInterval(function () {
      fetch("/notifications/unread", { headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d) return;
          var n = d.unread || 0;
          if (n > 0) {
            badge.textContent = n < 100 ? n : "99+";
            badge.hidden = false;
          } else {
            badge.hidden = true;
          }
        })
        .catch(function () {});
    }, 30000);
  }
})();
