// project.js
document.addEventListener('DOMContentLoaded', async () => {
    const keysContainer = document.getElementById('keys-container');
    const addKeyBtn = document.getElementById('add-key-btn');
    const keyModal = document.getElementById('key-modal');
    const keyForm = document.getElementById('key-form');
    const projectNameDisplay = document.getElementById('project-name-display');
    const projectTagDisplay = document.getElementById('project-tag-display');
    const decryptAllBtn = document.getElementById('decrypt-all-btn');

    const urlParams = new URLSearchParams(window.location.search);
    const projectId = urlParams.get('id');

    if (!projectId) {
        window.location.href = 'dashboard.html';
        return;
    }

    // Set page title and project info
    const currentProject = JSON.parse(sessionStorage.getItem('current_project'));
    if (currentProject) {
        projectNameDisplay.textContent = currentProject.name;
        projectTagDisplay.textContent = currentProject.tag || 'Project';
    }

    const loadKeys = async () => {
        try {
            const keys = await ApiClient.keys.getByProject(projectId);
            renderKeys(keys);
        } catch (err) {
            console.error(err);
        }
    };

    const renderKeys = (keys) => {
        keysContainer.innerHTML = '';
        if (keys.length === 0) {
            keysContainer.innerHTML = `
                <div style="padding: 6rem; text-align: center; border: 1px dashed var(--border-base); border-radius: var(--radius-xl); opacity: 0.6;">
                    <div style="font-size: 2.5rem; margin-bottom: 1.5rem;">🗝️</div>
                    <h3 style="margin-bottom: 0.5rem;">Vault is empty</h3>
                    <p class="text-muted">No security keys have been provisioned for this project yet.</p>
                </div>
            `;
            return;
        }

        keys.forEach(key => {
            const item = document.createElement('div');
            item.className = 'key-item';

            item.innerHTML = `
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Provider</div>
                    <div style="font-weight: 600; color: var(--text-main);">${key.service}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Identifier</div>
                    <div style="font-weight: 500;">${key.name}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Enviroment</div>
                    <span class="badge ${key.environment === 'prod' ? 'badge-prod' : 'badge-dev'}">${key.environment}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.75rem; background: var(--bg-muted); padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid var(--border-base);">
                    <code id="key-display-${key.id}" class="mono" style="background: transparent; padding: 0; min-width: 200px;" aria-label="Encrypted secret value">••••••••••••••••••••••••</code>
                    <div style="display: flex; gap: 0.25rem;">
                        <button class="btn btn-ghost" style="padding: 0.25rem; height: auto;" onclick="revealKey('${key.id}', '${key.encryptedValue}', '${key.iv}')" title="Reveal Sequence" aria-label="Reveal Secret">
                            <i class="fa-solid fa-eye" style="font-size: 0.8rem;"></i>
                        </button>
                        <button class="btn btn-ghost" style="padding: 0.25rem; height: auto;" onclick="copyKey('${key.id}', '${key.encryptedValue}', '${key.iv}')" title="Copy to Clipboard" aria-label="Copy Secret">
                            <i class="fa-solid fa-copy" style="font-size: 0.8rem;"></i>
                        </button>
                    </div>
                </div>
                <div style="text-align: right;">
                    <button class="btn btn-ghost" style="color: var(--error); padding: 0.5rem;" onclick="deleteKey('${key.id}')" title="Revoke Key" aria-label="Delete key">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;
            keysContainer.appendChild(item);
        });
    };

    const isExpired = (date) => {
        if (!date) return false;
        return new Date(date) < new Date();
    };

    // Modal controls
    addKeyBtn.onclick = () => {
        keyModal.style.display = 'flex';
        document.getElementById('key-name').focus();
    };
    document.getElementById('close-key-modal').onclick = () => keyModal.style.display = 'none';
    document.getElementById('cancel-key').onclick = () => keyModal.style.display = 'none';

    // Click outside to close
    window.onclick = (event) => {
        if (event.target == keyModal) {
            keyModal.style.display = 'none';
        }
    };

    keyForm.onsubmit = async (e) => {
        e.preventDefault();
        const saveBtn = document.getElementById('save-key-btn');
        saveBtn.disabled = true;
        saveBtn.textContent = 'Encrypting...';

        const name = document.getElementById('key-name').value;
        const service = document.getElementById('key-service').value;
        const env = document.getElementById('key-env').value;
        const rawValue = document.getElementById('key-value').value;
        const expiry = document.getElementById('key-expiry').value;
        const notes = document.getElementById('key-notes').value;

        const password = sessionStorage.getItem('master_password');
        const salt = localStorage.getItem('user_salt');

        try {
            // Encryption
            const cryptoKey = await CryptoModule.deriveKey(password, salt);
            const { ciphertext, iv } = await CryptoModule.encrypt(rawValue, cryptoKey);

            await ApiClient.keys.create({
                projectId,
                name,
                service,
                environment: env,
                encryptedValue: ciphertext,
                iv: iv,
                expiryDate: expiry,
                notes
            });

            keyModal.style.display = 'none';
            keyForm.reset();
            loadKeys();
        } catch (err) {
            alert('Operation failed: ' + err.message);
        } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Encrypt & Save';
        }
    };

    // Global functions for reveal/copy
    window.revealKey = async (id, ciphertext, iv) => {
        const display = document.getElementById(`key-display-${id}`);
        if (display.textContent !== '••••••••••••••••') {
            display.textContent = '••••••••••••••••';
            display.classList.remove('revealed');
            return;
        }

        try {
            const password = sessionStorage.getItem('master_password');
            const salt = localStorage.getItem('user_salt');
            const cryptoKey = await CryptoModule.deriveKey(password, salt);
            const plaintext = await CryptoModule.decrypt(ciphertext, iv, cryptoKey);
            display.textContent = plaintext;
            display.classList.add('revealed');
        } catch (err) {
            alert(err.message);
        }
    };

    window.copyKey = async (id, ciphertext, iv) => {
        try {
            const password = sessionStorage.getItem('master_password');
            const salt = localStorage.getItem('user_salt');
            const cryptoKey = await CryptoModule.deriveKey(password, salt);
            const plaintext = await CryptoModule.decrypt(ciphertext, iv, cryptoKey);
            navigator.clipboard.writeText(plaintext);
            alert('Key copied to clipboard');
        } catch (err) {
            alert(err.message);
        }
    };

    window.deleteKey = async (id) => {
        if (!confirm('Are you sure?')) return;
        try {
            await ApiClient.keys.delete(id);
            loadKeys();
        } catch (err) {
            alert(err.message);
        }
    };

    decryptAllBtn.onclick = async () => {
        const tiles = keysContainer.querySelectorAll('.key-tile');
        if (tiles.length === 0) return;

        alert('Decrypting vault...');
        const password = sessionStorage.getItem('master_password');
        const salt = localStorage.getItem('user_salt');

        try {
            const cryptoKey = await CryptoModule.deriveKey(password, salt);
            const keys = await ApiClient.keys.getByProject(projectId);

            keys.forEach(async (key) => {
                const display = document.getElementById(`key-display-${key.id}`);
                if (display) {
                    const plaintext = await CryptoModule.decrypt(key.encryptedValue, key.iv, cryptoKey);
                    display.textContent = plaintext;
                    display.classList.add('revealed');
                }
            });
        } catch (err) {
            alert('Decryption failed: ' + err.message);
        }
    };

    loadKeys();
});
