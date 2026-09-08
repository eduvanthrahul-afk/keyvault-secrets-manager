(function () {
    const savedTheme = localStorage.getItem('kb-theme') || 'system';

    const applyTheme = (theme) => {
        if (theme === 'system') {
            document.documentElement.removeAttribute('data-theme');
        } else {
            document.documentElement.setAttribute('data-theme', theme);
        }
    };

    applyTheme(savedTheme);

    // Listen for storage changes (for multiple tabs)
    window.addEventListener('storage', (e) => {
        if (e.key === 'kb-theme') {
            applyTheme(e.newValue || 'system');
        }
    });

    // Make it globally accessible for the settings page
    window.ThemeManager = {
        setTheme: (theme) => {
            localStorage.setItem('kb-theme', theme);
            applyTheme(theme);
        },
        getTheme: () => localStorage.getItem('kb-theme') || 'system'
    };
})();
