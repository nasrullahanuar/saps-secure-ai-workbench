(() => {
  const root = document.documentElement;
  const savedTheme = localStorage.getItem("saps-theme");
  if (savedTheme === "light" || savedTheme === "dark") root.dataset.theme = savedTheme;

  const themeButton = document.querySelector("[data-theme-toggle]");
  if (themeButton) {
    const setThemeLabel = () => {
      const target = root.dataset.theme === "dark" ? "light" : "dark";
      themeButton.setAttribute("aria-label", `Switch to ${target} mode`);
      themeButton.title = `Switch to ${target} mode`;
    };
    setThemeLabel();
    themeButton.addEventListener("click", () => {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      localStorage.setItem("saps-theme", next);
      setThemeLabel();
    });
  }

  const sidebar = document.querySelector("[data-sidebar]");
  const menuButton = document.querySelector("[data-menu-toggle]");
  if (sidebar && menuButton) {
    menuButton.addEventListener("click", () => {
      const open = sidebar.classList.toggle("is-open");
      menuButton.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", (event) => {
      if (window.innerWidth <= 820 && sidebar.classList.contains("is-open") &&
          !sidebar.contains(event.target) && !menuButton.contains(event.target)) {
        sidebar.classList.remove("is-open");
        menuButton.setAttribute("aria-expanded", "false");
      }
    });
  }

  const toast = document.querySelector("[data-toast]");
  if (toast) {
    const close = toast.querySelector("[data-toast-close]");
    if (close) close.addEventListener("click", () => { toast.hidden = true; });
    window.setTimeout(() => { toast.hidden = true; }, 5500);
  }

  const fileInput = document.querySelector("[data-file-input]");
  const dropZone = document.querySelector("[data-drop-zone]");
  const fileHint = document.querySelector("[data-file-hint]");
  if (fileInput && dropZone) {
    const updateFileHint = () => {
      const count = fileInput.files ? fileInput.files.length : 0;
      if (fileHint) fileHint.textContent = count ? `${count} file selected` : "Choose a file or drag it here";
    };
    fileInput.addEventListener("change", updateFileHint);
    ["dragenter", "dragover"].forEach((name) => dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    }));
    ["dragleave", "drop"].forEach((name) => dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
    }));
    dropZone.addEventListener("drop", (event) => {
      if (event.dataTransfer && event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        updateFileHint();
      }
    });
  }

  document.querySelectorAll("[data-upload-form]").forEach((form) => {
    form.addEventListener("submit", () => {
      const button = form.querySelector("[data-submit-button]");
      if (button) {
        button.classList.add("is-loading");
        button.disabled = true;
      }
    });
  });

  const table = document.querySelector("[data-documents-table]");
  if (table) {
    const rows = Array.from(table.querySelectorAll("tbody tr[data-document-row]"));
    const filters = { service: "all", classification: "all" };
    const search = document.querySelector("[data-document-search]");
    const updateRows = () => {
      const term = search ? search.value.trim().toLowerCase() : "";
      rows.forEach((row) => {
        const matchesService = filters.service === "all" || row.dataset.service === filters.service;
        const matchesClass = filters.classification === "all" || row.dataset.classification === filters.classification;
        const matchesText = !term || row.textContent.toLowerCase().includes(term);
        row.hidden = !(matchesService && matchesClass && matchesText);
      });
    };
    table.querySelectorAll("[data-filter-type]").forEach((button) => {
      button.addEventListener("click", () => {
        filters[button.dataset.filterType] = button.dataset.filterValue;
        table.querySelectorAll(`[data-filter-type="${button.dataset.filterType}"]`).forEach((peer) => {
          peer.classList.toggle("is-selected", peer === button);
          peer.setAttribute("aria-pressed", String(peer === button));
        });
        updateRows();
      });
    });
    if (search) search.addEventListener("input", updateRows);

    table.querySelectorAll("[data-sort-key]").forEach((button) => {
      button.addEventListener("click", () => {
        const key = button.dataset.sortKey;
        const direction = button.dataset.direction === "asc" ? "desc" : "asc";
        button.dataset.direction = direction;
        const body = table.querySelector("tbody");
        rows.sort((a, b) => {
          const left = (a.dataset[key] || "").toLowerCase();
          const right = (b.dataset[key] || "").toLowerCase();
          return left.localeCompare(right, undefined, { numeric: true }) * (direction === "asc" ? 1 : -1);
        }).forEach((row) => body.appendChild(row));
      });
    });
  }
})();
