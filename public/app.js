const toast = document.getElementById('toast');
let timer;
document.getElementById('year').textContent = new Date().getFullYear();
document.querySelectorAll('[data-plan]').forEach(button => {
  button.addEventListener('click', () => {
    toast.textContent = `${button.dataset.plan} is a demo plan. Live VPS ordering is not connected yet.`;
    toast.classList.add('show');
    clearTimeout(timer);
    timer = setTimeout(() => toast.classList.remove('show'), 3500);
  });
});
