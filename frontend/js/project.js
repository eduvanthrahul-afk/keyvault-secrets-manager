// project.js
document.addEventListener('DOMContentLoaded', async () => {
    const keysContainer = document.getElementById('keys-container');
    const addKeyBtn = document.getElementById('add-key-btn');
    const keyModal = document.getElementById('key-modal');
    const keyForm = document.getElementById('key-form');
    const projectNameDisplay = document.getElementById('project-name-display');
    const projectTagDisplay = document.getElementById('project-tag-display');
    const decryptAllBtn = document.getElementById('decrypt-all-btn');
    const keySearch = document.getElementById('key-search');

    // Token UI
    const tabSecrets = document.getElementById('tab-secrets');
    const tabTokens = document.getElementById('tab-tokens');
    const secretsView = document.getElementById('secrets-view');
    const tokensView = document.getElementById('tokens-view');
    const tokensContainer = document.getElementById('tokens-container');
    const addTokenBtn = document.getElementById('add-token-btn');
    const tokenModal = document.getElementById('token-modal');
    const tokenCreationForm = document.getElementById('token-creation-form');
    const tokenSuccessView = document.getElementById('token-success-view');
    const confirmTokenBtn = document.getElementById('confirm-token-btn');
    const generatedTokenDisplay = document.getElementById('generated-token-display');

    const urlParams = new URLSearchParams(window.location.search);
    const projectId = urlParams.get('id');

    let allKeys = [];

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
            allKeys = await ApiClient.keys.getByProject(projectId);
            renderKeys(allKeys);
        } catch (err) {
            console.error(err);
            keysContainer.innerHTML = `
                <div style="padding: 6rem; text-align: center; border: 1px solid var(--error-border); background: var(--error-bg); border-radius: var(--radius-xl);">
                    <div style="font-size: 2rem; margin-bottom: 1rem; color: var(--error);">⚠️</div>
                    <h3 style="margin-bottom: 0.5rem; color: var(--error);">Security synchronization failed</h3>
                    <p class="text-muted">${err.message}</p>
                    <button class="btn btn-ghost" onclick="window.location.reload()" style="margin-top: 1rem;">Reconnect to Vault</button>
                </div>
            `;
        }
    };

    const renderKeys = (keys) => {
        keysContainer.innerHTML = '';
        if (keys.length === 0) {
            keysContainer.innerHTML = `
                <div style="padding: 6rem; text-align: center; border: 1px dashed var(--border-base); border-radius: var(--radius-xl); opacity: 0.6;">
                    <div style="font-size: 2.5rem; margin-bottom: 1.5rem;">🗝️</div>
                    <h3 style="margin-bottom: 0.5rem;">${keySearch && keySearch.value ? 'No matching keys' : 'Vault is empty'}</h3>
                    <p class="text-muted">${keySearch && keySearch.value ? 'Try a different search term.' : 'No security keys have been provisioned for this project yet.'}</p>
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

    const loadTokens = async () => {
        try {
            const tokens = await ApiClient.tokens.getByProject(projectId);
            renderTokens(tokens);
        } catch (err) {
            notifications.showToast('Fetch Error', `Failed to load machine tokens: ${err.message}`, 'error');
        }
    };

    const renderTokens = (tokens) => {
        tokensContainer.innerHTML = '';
        if (tokens.length === 0) {
            tokensContainer.innerHTML = `
                <div style="padding: 4rem; text-align: center; border: 1px dashed var(--border-base); border-radius: var(--radius-xl); opacity: 0.6;">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">🤖</div>
                    <h3 style="margin-bottom: 0.5rem;">No Machine Tokens</h3>
                    <p class="text-muted">Generate a token to allow automated CI/CD access.</p>
                </div>
            `;
            return;
        }

        tokens.forEach(token => {
            const item = document.createElement('div');
            item.className = 'key-item';
            item.innerHTML = `
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase;">Label</div>
                    <div style="font-weight: 600;">${token.name}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase;">Token ID</div>
                    <code class="mono" style="font-size: 11px;">${token.tokenId}</code>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase;">Created</div>
                    <div class="text-muted" style="font-size: 12px;">${new Date(token.createdAt).toLocaleDateString()}</div>
                </div>
                <div style="text-align: right;">
                    <button class="btn btn-ghost" style="color: var(--error);" onclick="revokeToken('${token.id}')">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;
            tokensContainer.appendChild(item);
        });
    };

    if (keySearch) {
        keySearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = allKeys.filter(k =>
                k.name.toLowerCase().includes(query) ||
                k.service.toLowerCase().includes(query) ||
                k.environment.toLowerCase().includes(query)
            );
            renderKeys(filtered);
        });
    }

    // Tabs logic
    if (tabSecrets && tabTokens) {
        tabSecrets.onclick = () => {
            tabSecrets.classList.add('active');
            tabSecrets.style.borderBottom = '2px solid var(--primary)';
            tabSecrets.style.color = 'var(--text-primary)';
            tabTokens.classList.remove('active');
            tabTokens.style.borderBottom = '2px solid transparent';
            tabTokens.style.color = 'var(--text-secondary)';
            secretsView.style.display = 'block';
            tokensView.style.display = 'none';
        };

        tabTokens.onclick = () => {
            tabTokens.classList.add('active');
            tabTokens.style.borderBottom = '2px solid var(--primary)';
            tabTokens.style.color = 'var(--text-primary)';
            tabSecrets.classList.remove('active');
            tabSecrets.style.borderBottom = '2px solid transparent';
            tabSecrets.style.color = 'var(--text-secondary)';
            secretsView.style.display = 'none';
            tokensView.style.display = 'block';
            loadTokens();
        };
    }

    // Token Modals logic
    if (addTokenBtn) {
        addTokenBtn.onclick = () => {
            tokenModal.style.display = 'flex';
            tokenCreationForm.style.display = 'block';
            tokenSuccessView.style.display = 'none';
        };
        document.getElementById('close-token-modal').onclick = () => tokenModal.style.display = 'none';
        document.getElementById('cancel-token').onclick = () => tokenModal.style.display = 'none';
        document.getElementById('close-token-success').onclick = () => {
            tokenModal.style.display = 'none';
            loadTokens();
        };

        confirmTokenBtn.onclick = async () => {
            const name = document.getElementById('token-name').value.trim();
            if (!name) return notifications.showToast('Validation Error', 'Please provide a label for this token.', 'error');

            confirmTokenBtn.disabled = true;
            confirmTokenBtn.textContent = 'Securing...';

            try {
                // 1. Decrypt our master project key first
                const projectKey = await CryptoModule.getProjectKey(projectId);

                // 2. Generate a random Token Secret
                const tokenSecret = CryptoModule.generateSalt() + CryptoModule.generateSalt(); // 64 chars
                const tokenId = 'kv_' + CryptoModule.generateSalt().substring(0, 12);

                // 3. Hash the secret for backend verification
                const encoder = new TextEncoder();
                const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(tokenSecret));
                const tokenHash = CryptoModule.bufferToHex(hashBuffer);

                // 4. Encrypt project key with token secret
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const saltHex = CryptoModule.bufferToHex(salt);
                const ivHex = CryptoModule.bufferToHex(iv);

                // Use PBKDF2 to derive a key from the token secret
                const baseKey = await crypto.subtle.importKey('raw', encoder.encode(tokenSecret), 'PBKDF2', false, ['deriveKey']);
                const encKey = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                    baseKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['wrapKey']
                );

                const wrappedProjectKey = await crypto.subtle.wrapKey('raw', projectKey, encKey, { name: 'AES-GCM', iv: iv });
                const encryptedProjectKeyStr = saltHex + ':' + ivHex + ':' + CryptoModule.bufferToHex(wrappedProjectKey);

                // 5. Save to backend
                await ApiClient.tokens.create(projectId, {
                    name,
                    tokenId,
                    tokenHash,
                    encryptedProjectKey: encryptedProjectKeyStr
                });

                tokenCreationForm.style.display = 'none';
                tokenSuccessView.style.display = 'block';
                generatedTokenDisplay.textContent = tokenId + '.' + tokenSecret;

            } catch (err) {
                notifications.showToast('Provisioning Failed', err.message, 'error');
            } finally {
                confirmTokenBtn.disabled = false;
                confirmTokenBtn.textContent = 'Generate Pipeline Token';
            }
        };
    }

    window.revokeToken = async (id) => {
        const confirmed = await notifications.confirm('Revoke Token', 'This will immediately disconnect any CI/CD pipelines using this identity.', 'Revoke Identity', 'error');
        if (!confirmed) return;
        try {
            await ApiClient.tokens.delete(id);
            notifications.showToast('Identity Purged', 'Machine token killed.', 'success');
            loadTokens();
        } catch (err) {
            notifications.showToast('Revocation Error', err.message, 'error');
        }
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

    // Environment Custom Dropdown Logic
    const envToggle = document.getElementById('env-toggle');
    const envMenu = document.getElementById('env-menu');
    const envSelectedText = document.getElementById('env-selected-text');
    const envHiddenInput = document.getElementById('key-env');

    if (envToggle) {
        envToggle.onclick = (e) => {
            e.stopPropagation();
            envMenu.classList.toggle('show');
            envToggle.classList.toggle('active');
        };

        const envItems = envMenu.querySelectorAll('.dropdown-item');
        envItems.forEach(item => {
            item.onclick = () => {
                const val = item.getAttribute('data-value');
                envHiddenInput.value = val;
                envSelectedText.textContent = item.textContent.trim();

                envItems.forEach(i => i.classList.remove('selected'));
                item.classList.add('selected');

                envMenu.classList.remove('show');
                envToggle.classList.remove('active');
            };
        });
    }

    // Global close for all dropdowns
    document.addEventListener('click', () => {
        if (envMenu) {
            envMenu.classList.remove('show');
            envToggle.classList.remove('active');
        }
    });

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

        try {
            // Encryption
            let cryptoKey = await CryptoModule.getProjectKey(projectId);
            if (!cryptoKey) {
                notifications.showToast('Security Error', 'Failed to initialize project security vault.', 'error');
                return;
            }

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
            notifications.showToast('Key Provisioned', `Secret for "${name}" added to vault.`, 'success');
            loadKeys();
        } catch (err) {
            notifications.showToast('Provisioning Failed', err.message, 'error');
        } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Encrypt & Save';
        }
    };

    // Global functions for reveal/copy
    window.revealKey = async (id, ciphertext, iv) => {
        const display = document.getElementById(`key-display-${id}`);
        // Match with 24 dots as initialized in renderKeys
        if (display.textContent !== '••••••••••••••••••••••••') {
            display.textContent = '••••••••••••••••••••••••';
            display.classList.remove('revealed');
            return;
        }

        try {
            const cryptoKey = await CryptoModule.getProjectKey(projectId);
            if (!cryptoKey) throw new Error("Vault initialization error.");

            const plaintext = await CryptoModule.decrypt(ciphertext, iv, cryptoKey);
            display.textContent = plaintext;
            display.classList.add('revealed');
            notifications.showToast('Secret Revealed', 'Confidential data decrypted for viewing.', 'info');
        } catch (err) {
            notifications.showToast('Decryption Error', err.message, 'error');
        }
    };

    window.copyKey = async (id, ciphertext, iv) => {
        try {
            const cryptoKey = await CryptoModule.getProjectKey(projectId);
            if (!cryptoKey) throw new Error("Vault initialization error.");

            const plaintext = await CryptoModule.decrypt(ciphertext, iv, cryptoKey);
            navigator.clipboard.writeText(plaintext);
            notifications.showToast('Clipboard Sync', 'Secret copied to clipboard.', 'success');
        } catch (err) {
            notifications.showToast('Copy Failed', err.message, 'error');
        }
    };

    window.deleteKey = async (id) => {
        const confirmed = await notifications.confirm(
            'Revoke Security Key',
            'Are you sure you want to revoke this secret? Any applications using this key will experience immediate service interruption.',
            'Confirm Revoke'
        );
        if (!confirmed) return;

        try {
            await ApiClient.keys.delete(id);
            notifications.showToast('Key Revoked', 'The secret has been purged from the vault.', 'success');
            loadKeys();
        } catch (err) {
            notifications.showToast('Revocation Failed', err.message, 'error');
        }
    };

    decryptAllBtn.onclick = async () => {
        const items = keysContainer.querySelectorAll('.key-item');
        if (items.length === 0) return;

        notifications.showToast('Batch Decrypt', 'Initializing full vault decryption...', 'info');

        try {
            const cryptoKey = await CryptoModule.getProjectKey(projectId);
            if (!cryptoKey) throw new Error("Vault initialization error.");

            const keys = await ApiClient.keys.getByProject(projectId);

            keys.forEach(async (key) => {
                const display = document.getElementById(`key-display-${key.id}`);
                if (display) {
                    const plaintext = await CryptoModule.decrypt(key.encryptedValue, key.iv, cryptoKey);
                    display.textContent = plaintext;
                    display.classList.add('revealed');
                }
            });
            notifications.showToast('Vault Decrypted', 'All active secrets are now visible.', 'success');
        } catch (err) {
            notifications.showToast('Decryption Failed', err.message, 'error');
        }
    };

    // Premium Calendar Logic
    const calendarToggle = document.getElementById('calendar-toggle');
    const calendarPopup = document.getElementById('calendar-popup');
    const calendarGrid = document.getElementById('calendar-grid');
    const monthYearDisplay = document.getElementById('calendar-month-year');
    const hiddenExpiry = document.getElementById('key-expiry');
    const selectedText = document.getElementById('calendar-selected-text');

    let calCurrentDate = new Date();
    let calSelectedDate = null;

    const renderCalendar = (date) => {
        const year = date.getFullYear();
        const month = date.getMonth();
        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        const prevMonthDays = new Date(year, month, 0).getDate();

        const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
        monthYearDisplay.textContent = `${monthNames[month]} ${year}`;

        const labels = Array.from(calendarGrid.querySelectorAll('.calendar-day-label'));
        calendarGrid.innerHTML = '';
        labels.forEach(l => calendarGrid.appendChild(l));

        for (let i = firstDay - 1; i >= 0; i--) {
            const day = document.createElement('div');
            day.className = 'calendar-day other-month';
            day.textContent = prevMonthDays - i;
            calendarGrid.appendChild(day);
        }

        for (let i = 1; i <= daysInMonth; i++) {
            const day = document.createElement('div');
            day.className = 'calendar-day';
            day.textContent = i;

            const thisDate = new Date(year, month, i);
            const today = new Date();
            if (thisDate.toDateString() === today.toDateString()) day.classList.add('today');
            if (calSelectedDate && thisDate.toDateString() === calSelectedDate.toDateString()) day.classList.add('selected');

            day.onclick = (e) => {
                e.stopPropagation();
                calSelectedDate = thisDate;
                hiddenExpiry.value = thisDate.toISOString().split('T')[0];
                selectedText.textContent = thisDate.toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
                calendarPopup.classList.remove('show');
                calendarToggle.classList.remove('active');
                renderCalendar(date);
            };
            calendarGrid.appendChild(day);
        }
    };

    if (calendarToggle) {
        calendarToggle.onclick = (e) => {
            e.stopPropagation();
            const isOpen = calendarPopup.classList.contains('show');
            closeAllPopups();
            if (!isOpen) {
                calendarPopup.classList.add('show');
                calendarToggle.classList.add('active');
                renderCalendar(calCurrentDate);
            }
        };

        document.getElementById('prev-month').onclick = (e) => {
            e.stopPropagation();
            calCurrentDate.setMonth(calCurrentDate.getMonth() - 1);
            renderCalendar(calCurrentDate);
        };

        document.getElementById('next-month').onclick = (e) => {
            e.stopPropagation();
            calCurrentDate.setMonth(calCurrentDate.getMonth() + 1);
            renderCalendar(calCurrentDate);
        };

        document.getElementById('clear-date').onclick = (e) => {
            e.stopPropagation();
            calSelectedDate = null;
            hiddenExpiry.value = '';
            selectedText.textContent = 'No Expiration Set';
            closeAllPopups();
        };

        document.getElementById('set-today').onclick = (e) => {
            e.stopPropagation();
            calSelectedDate = new Date();
            calCurrentDate = new Date(calSelectedDate);
            hiddenExpiry.value = calSelectedDate.toISOString().split('T')[0];
            selectedText.textContent = calSelectedDate.toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
            closeAllPopups();
            renderCalendar(calCurrentDate);
        };
    }

    const closeAllPopups = () => {
        if (calendarPopup) calendarPopup.classList.remove('show');
        if (calendarToggle) calendarToggle.classList.remove('active');
        if (envMenu) {
            envMenu.classList.remove('show');
            envToggle.classList.remove('active');
        }
    };

    // Global close
    document.addEventListener('click', () => closeAllPopups());

    loadKeys();
});

