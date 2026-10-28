document.querySelectorAll('form[data-confirm]').forEach(form=>form.addEventListener('submit',event=>{if(!confirm(form.dataset.confirm))event.preventDefault()}));
(() => {
  const host = document.querySelector('#external_host');
  const port = document.querySelector('#external_port');
  const verb = document.querySelector('#verb');
  const output = document.querySelector('#profile-preview');
  if (!host || !port || !verb || !output) return;
  const protocol = output.textContent.match(/^proto\s+(\S+)/m)?.[1] || 'udp';
  const render = () => {
    const safeHost = host.value.trim().replace(/[\r\n]/g, '');
    const safePort = port.value.trim().replace(/\D/g, '');
    const safeVerb = verb.value.trim();
    output.textContent = ['client','dev tun','proto '+protocol,'remote '+safeHost+' '+safePort,
      'resolv-retry infinite','nobind','persist-key','persist-tun','remote-cert-tls server',
      'auth-nocache','pull-filter ignore "redirect-gateway"','verb '+safeVerb,
      '<ca> … </ca>','<cert> … </cert>','<key> … </key>','<tls-crypt> … </tls-crypt>'].join('\n');
  };
  [host,port,verb].forEach(field => field.addEventListener('input',render));
  render();
})();


/* Font preference is browser-local; the HTTPS application needs no external CDN. */
(() => {
  const fonts = new Set(['source', 'plex', 'inter']);
  const dropdown = document.getElementById('font-choice');
  let selected = 'source';
  try {
    const stored = localStorage.getItem('openvpn-control-font');
    if (fonts.has(stored)) selected = stored;
  } catch (_) { /* Private browsing may disable storage. */ }
  document.documentElement.dataset.uiFont = selected;
  if (dropdown) {
    dropdown.value = selected;
    dropdown.addEventListener('change', () => {
      if (!fonts.has(dropdown.value)) return;
      document.documentElement.dataset.uiFont = dropdown.value;
      try { localStorage.setItem('openvpn-control-font', dropdown.value); }
      catch (_) { /* Selection still works for this page. */ }
    });
  }
  document.querySelectorAll('time.last-connected[datetime]').forEach(el => {
    const date = new Date(el.dateTime);
    if (Number.isNaN(date.getTime())) return;
    el.textContent = new Intl.DateTimeFormat('ru-RU', {
      year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'
    }).format(date);
    el.title = 'Время в часовом поясе браузера';
  });
})();
