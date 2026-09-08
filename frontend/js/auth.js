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
                // Fetch salt first for client-side hashing
                const saltRes = await ApiClient.auth.getSalt(email);
                const salt = saltRes.salt;

                // Stage 1: Generate Auth_Hash
                const authHash = await CryptoModule.generateAuthHash(password, salt);

                const response = await ApiClient.auth.login({ email, password: authHash });
                if (response.token) localStorage.setItem('jwt_token', response.token);
                localStorage.setItem('user_email', response.email);
                sessionStorage.setItem('user_salt', response.salt);

                // --- IDENTITY UPGRADE FOR LEGACY ACCOUNTS ---
                if (!response.publicKey) {
                    notifications.showToast('Security Patch', 'Provisioning Zero-Knowledge identity for legacy account...', 'info');
                    const upgradeSessionKey = await CryptoModule.deriveKey(authHash, response.salt);
                    const rsaKeyPair = await CryptoModule.generateRSAKeyPair();
                    const publicKey = await CryptoModule.exportPublicKey(rsaKeyPair);
                    const encryptedPrivateKey = await CryptoModule.exportAndEncryptPrivateKey(rsaKeyPair, upgradeSessionKey);

                    await ApiClient.auth.updateIdentity({ publicKey, encryptedPrivateKey });

                    response.publicKey = publicKey;
                    response.encryptedPrivateKey = encryptedPrivateKey;
                }

                if (response.publicKey) sessionStorage.setItem('public_key', response.publicKey);
                if (response.encryptedPrivateKey) sessionStorage.setItem('encrypted_private_key', response.encryptedPrivateKey);

                // Stage 2: Derive Master_Encryption_Key from Auth_Hash
                const sessionKey = await CryptoModule.deriveKey(authHash, response.salt);
                await CryptoModule.saveSessionKey(sessionKey);

                notifications.showToast('Access Granted', 'Initializing secure session...', 'success');
                setTimeout(() => window.location.href = 'dashboard.html', 800);
            } catch (err) {
                notifications.showToast('Login Blocked', err.message, 'error');
            }
        });
    }

    if (registerForm) {
        const otpModal = document.getElementById('otp-modal');
        const otpInput = document.getElementById('otp-input');
        const verifyOtpBtn = document.getElementById('verify-otp-btn');
        const cancelOtpBtn = document.getElementById('cancel-otp');
        const resendOtpLink = document.getElementById('resend-otp-link');

        let pendingRegistration = null;

        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm-password').value;

            if (password !== confirm) {
                notifications.showToast('Validation Error', 'Password mismatch detected.', 'warning');
                return;
            }

            // Strong Email Validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                notifications.showToast('Invalid Email', 'Please enter a valid work email address.', 'warning');
                return;
            }

            try {
                notifications.showToast('Identity Verification', 'Dispatched code to ' + email, 'info');
                await ApiClient.auth.requestOtp(email);

                // Store details for final step
                pendingRegistration = { email, password };

                // Show Modal
                otpModal.style.display = 'flex';
                otpInput.focus();
            } catch (err) {
                notifications.showToast('Verification Failed', err.message, 'error');
            }
        });

        const finalizeRegistration = async () => {
            if (!pendingRegistration) return;
            const { email, password } = pendingRegistration;
            const code = otpInput.value.trim();

            if (code.length !== 6) {
                notifications.showToast('Entry Error', 'Please enter the full 6-digit code.', 'warning');
                return;
            }

            try {
                verifyOtpBtn.disabled = true;
                verifyOtpBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Verifying...';

                // 1. Verify OTP with Server
                await ApiClient.auth.verifyOtp(email, code);

                notifications.showToast('Success', 'Email verified. Provisioning security vault...', 'success');

                // 2. Proceed with Zero-Knowledge Crypto
                const salt = CryptoModule.generateSalt();
                const authHash = await CryptoModule.generateAuthHash(password, salt);
                const sessionKey = await CryptoModule.deriveKey(authHash, salt);
                const rsaKeyPair = await CryptoModule.generateRSAKeyPair();

                const publicKey = await CryptoModule.exportPublicKey(rsaKeyPair);
                const encryptedPrivateKey = await CryptoModule.exportAndEncryptPrivateKey(rsaKeyPair, sessionKey);

                // 3. Register final product
                await ApiClient.auth.register({ email, password: authHash, salt, publicKey, encryptedPrivateKey });

                otpModal.style.display = 'none';
                notifications.showToast('Account Created', 'Architecture registry updated. Please login.', 'success');
                setTimeout(() => window.location.href = 'login.html', 1500);
            } catch (err) {
                notifications.showToast('Registration Failure', err.message, 'error');
                verifyOtpBtn.disabled = false;
                verifyOtpBtn.textContent = 'Verify & Register';
            }
        };

        verifyOtpBtn.onclick = finalizeRegistration;

        cancelOtpBtn.onclick = () => {
            otpModal.style.display = 'none';
            pendingRegistration = null;
        };

        resendOtpLink.onclick = async (e) => {
            e.preventDefault();
            if (!pendingRegistration) return;
            try {
                await ApiClient.auth.requestOtp(pendingRegistration.email);
                notifications.showToast('Code Re-sent', 'Check your inbox for a fresh code.', 'success');
            } catch (err) {
                notifications.showToast('Error', err.message, 'error');
            }
        };

        // Handle enter key in OTP
        otpInput.onkeyup = (e) => {
            if (e.key === 'Enter') finalizeRegistration();
        };
    }

});

