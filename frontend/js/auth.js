// auth.js
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await ApiClient.auth.login({ email, password });
                localStorage.setItem('jwt_token', response.token);
                localStorage.setItem('user_email', response.email);
                localStorage.setItem('user_salt', response.salt);
                if (response.publicKey) localStorage.setItem('public_key', response.publicKey);
                if (response.encryptedPrivateKey) localStorage.setItem('encrypted_private_key', response.encryptedPrivateKey);

                const sessionKey = await CryptoModule.deriveKey(password, response.salt);
                await CryptoModule.saveSessionKey(sessionKey);

                notifications.showToast('Access Granted', 'Initializing secure session...', 'success');
                setTimeout(() => window.location.href = 'dashboard.html', 800);
            } catch (err) {
                notifications.showToast('Login Blocked', err.message, 'error');
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm-password').value;

            if (password !== confirm) {
                notifications.showToast('Validation Error', 'Password mismatch detected.', 'warning');
                return;
            }

            const salt = CryptoModule.generateSalt();

            try {
                // Generate Zero-Knowledge RSA Identity
                const sessionKey = await CryptoModule.deriveKey(password, salt);
                const rsaKeyPair = await CryptoModule.generateRSAKeyPair();

                const publicKey = await CryptoModule.exportPublicKey(rsaKeyPair);
                const encryptedPrivateKey = await CryptoModule.exportAndEncryptPrivateKey(rsaKeyPair, sessionKey);

                await ApiClient.auth.register({ email, password, salt, publicKey, encryptedPrivateKey });
                notifications.showToast('Account Created', 'Architecture registry updated. Please login.', 'success');
                setTimeout(() => window.location.href = 'login.html', 1500);
            } catch (err) {
                notifications.showToast('Registration Failure', err.message, 'error');
            }
        });
    }

    // Explicit Logout for auth pages context
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.onclick = async (e) => {
            e.preventDefault();
            const confirmed = await notifications.confirm('End Session', 'Are you sure you want to logout?', 'Sign Out', 'info');
            if (confirmed) {
                localStorage.clear();
                sessionStorage.clear();
                if (typeof CryptoModule !== 'undefined' && CryptoModule.clearSessionVault) {
                    await CryptoModule.clearSessionVault();
                }
                window.location.href = 'login.html';
            }
        };
    }
});

