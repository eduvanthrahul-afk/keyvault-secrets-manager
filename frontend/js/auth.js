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

                // Store password in sessionStorage for the duration of the tab session
                // This allows key derivation without re-prompting every time
                sessionStorage.setItem('master_password', password);

                window.location.href = 'dashboard.html';
            } catch (err) {
                alert('Login failed: ' + err.message);
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
                alert('Passwords do not match');
                return;
            }

            // Generate a fresh salt for this user
            const salt = CryptoModule.generateSalt();

            try {
                await ApiClient.auth.register({ email, password, salt });
                alert('Registration successful! Please login.');
                window.location.href = 'login.html';
            } catch (err) {
                alert('Registration failed: ' + err.message);
            }
        });
    }

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = 'login.html';
        });
    }
});
