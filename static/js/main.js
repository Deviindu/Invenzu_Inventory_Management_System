// invenzu - Main Client JS
document.addEventListener('DOMContentLoaded', () => {

  // Auto-dismiss toast alerts after 4s
  const toasts = document.querySelectorAll('.toast');

  toasts.forEach(t => {
    setTimeout(() => {
      t.style.opacity = '0';
      t.style.transition = 'opacity 0.5s ease';

      setTimeout(() => t.remove(), 500);
    }, 4000);
  });


  // Logout modal trigger
  const logoutTriggers = document.querySelectorAll('.trigger-logout');
  const logoutModal = document.getElementById('logout-modal');
  const cancelLogout = document.getElementById('cancel-logout');

  if (logoutModal) {

    logoutTriggers.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        logoutModal.classList.add('open');
      });
    });

    if (cancelLogout) {
      cancelLogout.addEventListener('click', () => {
        logoutModal.classList.remove('open');
      });
    }

    logoutModal.addEventListener('click', (e) => {
      if (e.target === logoutModal) {
        logoutModal.classList.remove('open');
      }
    });

  }


  // Notification dropdown
  const notificationBell = document.getElementById('notificationBell');
  const notificationDropdown = document.getElementById('notificationDropdown');

  if (notificationBell && notificationDropdown) {

    notificationBell.addEventListener('click', (e) => {
      e.stopPropagation();
      notificationDropdown.classList.toggle('show');
    });

    notificationDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
    });

    document.addEventListener('click', () => {
      notificationDropdown.classList.remove('show');
    });

  }

});