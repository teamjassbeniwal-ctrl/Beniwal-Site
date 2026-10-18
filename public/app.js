const loginTab = document.getElementById('login-tab');
const registerTab = document.getElementById('register-tab');
const form = document.getElementById('auth-form');
const title = document.getElementById('form-title');
const password = document.getElementById('password');
const hint = document.getElementById('password-hint');
const submitBtn = document.getElementById('submit-btn');
const message = document.getElementById('message');
const dashboard = document.getElementById('dashboard');
const authCard = document.getElementById('auth-card');
let mode = 'login';

function showMessage(el, text, good = false) {
  el.textContent = text;
  el.classList.toggle('good', good);
}
function setMode(next) {
  mode = next;
  loginTab.classList.toggle('active', mode === 'login');
  registerTab.classList.toggle('active', mode === 'register');
  title.textContent = mode === 'login' ? 'Log in to your account' : 'Create your account';
  submitBtn.textContent = mode === 'login' ? 'Login' : 'Create account';
  password.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  hint.hidden = mode !== 'register';
  message.textContent = '';
}
loginTab.addEventListener('click', () => setMode('login'));
registerTab.addEventListener('click', () => setMode('register'));

form.addEventListener('submit', async event => {
  event.preventDefault();
  submitBtn.disabled = true;
  showMessage(message, 'Please wait…');
  const payload = {
    email: document.getElementById('email').value.trim(),
    password: password.value
  };
  try {
    const response = await fetch(`/api/${mode}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed.');
    password.value = '';
    await loadAccount();
    showMessage(document.getElementById('dashboard-message'), data.message || 'Success.', true);
  } catch (err) {
    showMessage(message, err.message || 'Could not connect. Try again.');
  } finally {
    submitBtn.disabled = false;
  }
});

async function loadAccount() {
  try {
    const response = await fetch('/api/me', { credentials: 'same-origin' });
    if (!response.ok) {
      form.hidden = false;
      dashboard.hidden = true;
      return;
    }
    const data = await response.json();
    document.getElementById('account-email').textContent = data.user.email;
    form.hidden = true;
    dashboard.hidden = false;
  } catch (_) {
    showMessage(message, 'Could not check your login status. Refresh the page.');
  }
}

document.getElementById('logout-btn').addEventListener('click', async () => {
  const btn = document.getElementById('logout-btn');
  btn.disabled = true;
  try {
    const response = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin'
    });
    if (!response.ok) throw new Error('Logout failed. Please try again.');
    dashboard.hidden = true;
    form.hidden = false;
    form.reset();
    setMode('login');
    showMessage(message, 'You have logged out.', true);
  } catch (err) {
    showMessage(document.getElementById('dashboard-message'), err.message);
  } finally {
    btn.disabled = false;
  }
});

loadAccount();
