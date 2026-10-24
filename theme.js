// Applies your saved theme before the page paints (so there is no white/black flash).
(function () {
  try {
    var c = JSON.parse(localStorage.getItem('hariom_cfg') || '{}');
    var t = c.theme || 'light';
    if (t === 'auto') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
  } catch (e) {
    document.documentElement.dataset.theme = 'light';
  }
})();
