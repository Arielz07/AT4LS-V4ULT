(() => {
  "use strict";

  const root = document.documentElement;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const isOwner = document.querySelector('meta[name="atl4s-owner"]')?.content === "1";
  const media = window.matchMedia("(prefers-color-scheme: light)");

  const resolveTheme = (pref) => (pref === "auto" ? (media.matches ? "light" : "dark") : pref);
  const applyTheme = (pref, persist = true) => {
    const resolved = resolveTheme(pref);
    root.dataset.theme = resolved;
    root.dataset.themePref = pref;
    if (persist) {
      try { localStorage.setItem("atl4s-theme", pref); } catch (err) {}
    }
    document.querySelectorAll("[data-set-theme]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.setTheme === pref);
    });
  };

  applyTheme((() => {
    try { return localStorage.getItem("atl4s-theme") || root.dataset.themePref || "auto"; }
    catch (err) { return "auto"; }
  })(), false);

  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      applyTheme(root.dataset.theme === "dark" ? "light" : "dark");
    });
  });
  document.querySelectorAll("[data-set-theme]").forEach((button) => {
    button.addEventListener("click", () => applyTheme(button.dataset.setTheme));
  });
  media.addEventListener("change", () => {
    if (root.dataset.themePref === "auto") applyTheme("auto", false);
  });

  const applyScene = (scene, persist = true) => {
    root.dataset.scene = scene || "drift";
    if (persist) {
      try { localStorage.setItem("atl4s-scene", root.dataset.scene); } catch (err) {}
    }
    document.querySelectorAll("[data-set-scene]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.setScene === root.dataset.scene);
    });
  };
  applyScene((() => {
    try { return localStorage.getItem("atl4s-scene") || "drift"; }
    catch (err) { return "drift"; }
  })(), false);
  document.querySelectorAll("[data-set-scene]").forEach((button) => {
    button.addEventListener("click", () => applyScene(button.dataset.setScene));
  });

  const body = document.body;
  const railToggle = document.querySelector("[data-rail-toggle]");
  const railScrim = document.querySelector("[data-rail-scrim]");
  const closeRail = () => body.classList.remove("rail-open");
  railToggle?.addEventListener("click", () => body.classList.toggle("rail-open"));
  railScrim?.addEventListener("click", closeRail);
  document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", closeRail));

  const searchInput = document.querySelector("[data-search-input]");
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      searchInput?.focus();
      searchInput?.select();
    }
    if (event.key === "Escape" && document.activeElement === searchInput) searchInput.blur();
  });

  document.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = button.closest(".input-with-action")?.querySelector("input");
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
      button.setAttribute("aria-label", input.type === "password" ? "Show password" : "Hide password");
    });
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const text = button.dataset.copy || "";
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
      } catch (err) {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); } catch (copyErr) {}
        area.remove();
      }
      const previous = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = previous; }, 1600);
    });
  });

  document.querySelectorAll("[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-close-flash]").forEach((button) => {
    button.addEventListener("click", () => button.closest("[data-flash]")?.remove());
  });
  window.setTimeout(() => {
    document.querySelectorAll("[data-flash]").forEach((flash) => {
      flash.style.transition = "opacity .35s ease, transform .35s ease";
      flash.style.opacity = "0";
      flash.style.transform = "translateY(-4px)";
      window.setTimeout(() => flash.remove(), 400);
    });
  }, 7000);

  if (csrf) {
    let heartbeatTimer = null;
    let locking = false;
    const lockPage = () => {
      if (locking) return;
      locking = true;
      window.location.assign("/locked");
    };
    const heartbeat = async () => {
      if (document.visibilityState === "hidden") return;
      try {
        const response = await fetch("/api/presence", {
          method: "POST",
          headers: { "X-CSRF": csrf, "Accept": "application/json" },
          credentials: "same-origin",
          keepalive: true,
        });
        if (response.status === 401 || response.status === 403) {
          lockPage();
          return;
        }
        const state = await response.json();
        if (state && state.vault_open === false) lockPage();
      } catch (err) {}
    };
    const start = () => {
      heartbeat();
      if (heartbeatTimer) window.clearInterval(heartbeatTimer);
      heartbeatTimer = window.setInterval(heartbeat, 15000);
    };
    const closePresence = () => {
      try {
        navigator.sendBeacon(`/api/presence/close?csrf=${encodeURIComponent(csrf)}`);
      } catch (err) {}
    };
    start();
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") start();
    });
    window.addEventListener("pageshow", start);
    if (isOwner) {
      window.addEventListener("pagehide", closePresence);
      window.addEventListener("beforeunload", closePresence);
    }
  }
})();
