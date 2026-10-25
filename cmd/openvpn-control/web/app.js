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
