(() => {
  const fonts = new Set(['source', 'plex', 'inter']);
  const dropdown = document.getElementById('font-choice');
  let selected = 'source';
  try {
    const stored = localStorage.getItem('openvpn-control-font');
    if (fonts.has(stored)) selected = stored;
  } catch (_) {}
  document.documentElement.dataset.uiFont = selected;
  if (dropdown) {
    dropdown.value = selected;
    dropdown.addEventListener('change', () => {
      if (!fonts.has(dropdown.value)) return;
      document.documentElement.dataset.uiFont = dropdown.value;
      try { localStorage.setItem('openvpn-control-font', dropdown.value); } catch (_) {}
    });
  }

  // Color theme is independent of the font preference, and shared with login.
  const themes = new Set(['sage', 'mist']);
  const themeDropdown = document.getElementById('theme-choice');
  let theme = 'sage';
  try {
    const savedTheme = localStorage.getItem('openvpn-control-theme');
    if (themes.has(savedTheme)) theme = savedTheme;
  } catch (_) { /* Private browsing may disallow storage. */ }
  document.documentElement.dataset.uiTheme = theme;
  if (themeDropdown) {
    themeDropdown.value = theme;
    themeDropdown.addEventListener('change', () => {
      if (!themes.has(themeDropdown.value)) return;
      document.documentElement.dataset.uiTheme = themeDropdown.value;
      try { localStorage.setItem('openvpn-control-theme', themeDropdown.value); }
      catch (_) { /* Still applies until the next page load. */ }
    });
  }

  const host = document.getElementById('external-host');
  const port = document.getElementById('external-port');
  const verb = document.getElementById('verb');
  const sync = () => {
    const ph = document.getElementById('preview-host');
    const pp = document.getElementById('preview-port');
    const pv = document.getElementById('preview-verb');
    if (ph) ph.textContent = host?.value || '—';
    if (pp) pp.textContent = port?.value || '—';
    if (pv) pv.textContent = verb?.value || '0';
  };
  [host, port, verb].forEach(el => el && el.addEventListener('input', sync));
  sync();

  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', e => {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  document.querySelectorAll('time.last-connected[datetime]').forEach(el => {
    const date = new Date(el.dateTime);
    if (Number.isNaN(date.getTime())) return;
    el.textContent = new Intl.DateTimeFormat('ru-RU', {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(date);
    el.title = 'Время в часовом поясе браузера';
  });
})();