'use strict';

function uiText(key, fallback) {
  return document.body.getAttribute('data-' + key) || fallback;
}

function copyValue(el) {
  const value = 'value' in el && el.tagName === 'INPUT' ? el.value : el.textContent.trim();
  const done = () => flashCopied(el);
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).then(done).catch(() => fallbackCopy(el, value, done));
  } else {
    fallbackCopy(el, value, done);
  }
}

function fallbackCopy(el, value, done) {
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.append(ta);
  ta.select();
  try {
    document.execCommand('copy');
  } catch (_) {
    // Nothing more we can do without clipboard access.
  }
  ta.remove();
  done();
}

function flashCopied(el) {
  el.classList.add('copied-flash');
  setTimeout(() => el.classList.remove('copied-flash'), 500);
  const rect = el.getBoundingClientRect();
  const badge = document.createElement('span');
  badge.className = 'copied-badge';
  badge.textContent = uiText('copied', 'Copied');
  document.body.append(badge);
  badge.style.left = Math.round(rect.left + rect.width / 2) + 'px';
  badge.style.top = Math.round(rect.top) + 'px';
  requestAnimationFrame(() => badge.classList.add('show'));
  setTimeout(() => {
    badge.classList.remove('show');
    setTimeout(() => badge.remove(), 200);
  }, 1100);
}

document.addEventListener('click', event => {
  const el = event.target.closest('.copyable');
  if (!el) return;
  event.preventDefault();
  if (el.tagName === 'INPUT') el.select();
  copyValue(el);
});


function closeDialog(dialog) {
  if (dialog && dialog.open) dialog.close();
}

function setSidebar(open) {
  document.body.classList.toggle('sidebar-open', open);
  const backdrop = document.querySelector('[data-sidebar-backdrop]');
  if (backdrop) backdrop.hidden = !open;
  const toggle = document.querySelector('[data-sidebar-toggle]');
  if (toggle) toggle.setAttribute('aria-expanded', String(open));
}

document.addEventListener('click', event => {
  if (event.target.closest('[data-sidebar-toggle]')) {
    setSidebar(!document.body.classList.contains('sidebar-open'));
  }
  if (event.target.closest('[data-sidebar-backdrop]')) {
    setSidebar(false);
  }
  if (window.matchMedia('(max-width: 768px)').matches && event.target.closest('.side-nav a')) {
    setSidebar(false);
  }

  const closeButton = event.target.closest('[data-dialog-close]');
  if (closeButton) closeDialog(closeButton.closest('dialog'));

  const toggle = event.target.closest('.password-toggle');
  if (toggle) {
    const input = toggle.parentElement.querySelector('input');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? uiText('hide-pass', 'Hide') : uiText('show-pass', 'Show');
    toggle.setAttribute('aria-label', toggle.textContent);
  }

  const editButton = event.target.closest('.edit-user-button');
  if (editButton) {
    const dialog = document.getElementById('edit-user-dialog');
    document.getElementById('edit-user-name').value = editButton.dataset.user;
    document.getElementById('edit-user-label').textContent = editButton.dataset.user;
    document.getElementById('edit-user-expires').value = editButton.dataset.expires;
    document.getElementById('edit-user-quota').value = editButton.dataset.quota;
    const ike = document.getElementById('edit-user-ikev2');
    const l2 = document.getElementById('edit-user-l2tp');
    if (ike) ike.checked = editButton.dataset.ikev2 !== '0';
    if (l2) l2.checked = editButton.dataset.l2tp !== '0';
    document.getElementById('edit-user-ss').checked = editButton.dataset.ss === '1';
    document.getElementById('edit-user-hy').checked = editButton.dataset.hy === '1';
    document.getElementById('edit-user-vless').checked = editButton.dataset.vless === '1';
    const vmess = document.getElementById('edit-user-vmess');
    const http = document.getElementById('edit-user-http');
    const mtg = document.getElementById('edit-user-mtg');
    if (vmess) vmess.checked = editButton.dataset.vmess === '1';
    if (http) http.checked = editButton.dataset.http === '1';
    if (mtg) mtg.checked = editButton.dataset.mtg === '1';
    dialog.showModal();
  }
});

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && document.body.classList.contains('sidebar-open')) setSidebar(false);
});

document.querySelectorAll('dialog').forEach(dialog => {
  dialog.addEventListener('click', event => {
    if (event.target === dialog) closeDialog(dialog);
  });
});

document.addEventListener('submit', event => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;

  if (form.dataset.confirm && form.dataset.confirmed !== 'true') {
    event.preventDefault();
    const dialog = document.getElementById('confirm-dialog');
    document.getElementById('confirm-title').textContent = form.dataset.confirmTitle || '';
    document.getElementById('confirm-message').textContent = form.dataset.confirm;
    dialog.returnValue = '';
    dialog.showModal();
    dialog.addEventListener('close', () => {
      if (dialog.returnValue === 'confirm') {
        form.dataset.confirmed = 'true';
        form.requestSubmit();
      }
    }, {once: true});
    return;
  }

  const submitter = event.submitter || form.querySelector('[type="submit"]');
  if (!submitter) return;
  submitter.disabled = true;
  submitter.classList.add('is-loading');
  submitter.dataset.originalText = submitter.textContent;
  submitter.textContent = uiText('working', '…');
  form.setAttribute('aria-busy', 'true');
});

window.addEventListener('pageshow', () => {
  document.querySelectorAll('form[aria-busy="true"]').forEach(form => {
    form.removeAttribute('aria-busy');
    const button = form.querySelector('.is-loading');
    if (button) {
      button.disabled = false;
      button.classList.remove('is-loading');
      button.textContent = button.dataset.originalText || button.textContent;
    }
  });
});

