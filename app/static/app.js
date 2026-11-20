/* Shared helpers for dupe-checker pages. */
function csrfToken() {
  const meta = document.querySelector('meta[name="csrf"]');
  return meta ? meta.getAttribute('content') : '';
}

async function api(method, url, body) {
  const opts = {
    method,
    credentials: 'same-origin',
    headers: { 'Accept': 'application/json' },
  };
  if (body !== undefined && body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-CSRF-Token'] = csrfToken();
    opts.body = JSON.stringify(body);
  }
  try {
    const res = await fetch(url, opts);
    let data = {};
    const type = res.headers.get('content-type') || '';
    if (type.includes('application/json')) {
      data = await res.json();
    } else {
      data = { raw: await res.text() };
    }
    if (res.status === 401) {
      location.href = '/login';
    }
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { error: { message: String(err) } } };
  }
}

window.api = api;
window.csrfToken = csrfToken;
