const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'frontend');
const files = ['landing.html', 'login.html', 'register.html', 'dashboard.html', 'project.html', 'teams.html', 'audit.html', 'settings.html', 'js/crypto.js', 'js/api.js'];

const svg = `<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" style="display:block;margin:auto;"><polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"></polygon><line x1="12" y1="22" x2="12" y2="15.5"></line><polyline points="22 8.5 12 15.5 2 8.5"></polyline><polyline points="2 15.5 12 8.5 22 15.5"></polyline><line x1="12" y1="2" x2="12" y2="8.5"></line></svg>`;

for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.existsSync(fullPath)) {
        let content = fs.readFileSync(fullPath, 'utf8');

        // Replace KeyVault with Kypher globally
        content = content.replace(/KeyVault/g, 'Kypher');

        // Replace vault icons with sleek SVG
        content = content.replace(/<i class="fa-solid fa-vault".*?><\/i>/g, svg);

        // Replace landing page K box
        content = content.replace(/<div class="logo-box">K<\/div>/g, '<div class="logo-box">' + svg + '</div>');

        fs.writeFileSync(fullPath, content);
        console.log(`Updated ${file}`);
    }
}
