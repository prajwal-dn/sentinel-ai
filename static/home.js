'use strict';
(() => {
  const root = document.documentElement;
  const themeButton = document.getElementById('theme-toggle');
  const menuButton = document.getElementById('menu-toggle');
  const mobileNav = document.getElementById('main-nav-mobile');
  const heroVideo = document.querySelector('.hero-video');
  const storageKey = 'sentinel-home-theme';
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  function applyTheme(theme, persist = true) {
    const normalized = theme === 'light' ? 'light' : 'dark';
    root.dataset.theme = normalized;
    const next = normalized === 'dark' ? 'light' : 'dark';
    if (themeButton) {
      themeButton.setAttribute('aria-label', `Switch to ${next} mode`);
      themeButton.setAttribute('title', `Switch to ${next} mode`);
      themeButton.setAttribute('aria-pressed', String(normalized === 'light'));
    }
    if (persist) {
      try { localStorage.setItem(storageKey, normalized); } catch (_) { /* Storage can be disabled. */ }
    }
  }

  let initialTheme = 'dark';
  try {
    const saved = localStorage.getItem(storageKey);
    if (saved === 'light' || saved === 'dark') initialTheme = saved;
  } catch (_) { /* Default to dark mode. */ }
  applyTheme(initialTheme, false);

  themeButton?.addEventListener('click', () => applyTheme(root.dataset.theme === 'dark' ? 'light' : 'dark'));

  function closeMenu() {
    if (!mobileNav || !menuButton) return;
    mobileNav.hidden = true;
    menuButton.setAttribute('aria-expanded', 'false');
    menuButton.setAttribute('aria-label', 'Open navigation');
  }
  menuButton?.addEventListener('click', () => {
    const open = menuButton.getAttribute('aria-expanded') !== 'true';
    mobileNav.hidden = !open;
    menuButton.setAttribute('aria-expanded', String(open));
    menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  });
  mobileNav?.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
  document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenu(); });

  if (heroVideo && reducedMotion.matches) {
    heroVideo.pause();
    heroVideo.removeAttribute('autoplay');
  }
  reducedMotion.addEventListener?.('change', event => {
    if (!heroVideo) return;
    if (event.matches) { heroVideo.pause(); heroVideo.removeAttribute('autoplay'); }
    else { heroVideo.setAttribute('autoplay', 'autoplay'); heroVideo.play().catch(() => {}); }
  });

  const revealItems = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && !reducedMotion.matches) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -30px 0px' });
    revealItems.forEach(el => observer.observe(el));
  } else {
    revealItems.forEach(el => el.classList.add('is-visible'));
  }
})();
