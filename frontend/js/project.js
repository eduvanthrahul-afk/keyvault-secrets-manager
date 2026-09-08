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
            // Secret Loading State (Skeletons)
            keysContainer.innerHTML = Array(4).fill(0).map(() => `
                <div style="padding: 1.5rem; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--surface-1); margin-bottom: 20px;">
                    <div class="skeleton skeleton-title" style="width: 40%; margin-bottom: 24px;"></div>
                    <div style="display: flex; gap: 32px; flex-wrap: wrap;">
                        <div style="flex: 1; min-width: 200px;">
                            <div class="skeleton-text skeleton" style="width: 30%; margin-bottom: 8px;"></div>
                            <div class="skeleton-text skeleton" style="width: 60%;"></div>
                        </div>
                        <div style="flex: 2; min-width: 300px;">
                            <div class="skeleton-text skeleton" style="width: 20%; margin-bottom: 8px;"></div>
                            <div class="skeleton-text skeleton" style="width: 80%;"></div>
                        </div>
                    </div>
                </div>
            `).join('');

            allKeys = await ApiClient.keys.getByProject(projectId);
            if (!allKeys) return; // Session expiration handled globally

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
                    <h3 style="margin-bottom: 0.5rem;">${(keySearch && keySearch.value) ? 'No matching keys' : 'Vault is empty'}</h3>
                    <p class="text-muted">${(keySearch && keySearch.value) ? `No keys in the vault match the term "${esc(keySearch.value)}".` : 'No security keys have been provisioned for this project yet.'}</p>
                </div>
            `;
            return;
        }

        keys.forEach(key => {
            console.log(`[Debug] Rendering key: ${key.name} (v${key.version})`);
            const item = document.createElement('div');
            item.className = 'key-item';

            item.innerHTML = `
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Provider</div>
                    <div style="font-weight: 600; color: var(--text-main);">${esc(key.service)}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Identifier</div>
                    <div style="font-weight: 500;">${esc(key.name)}</div>
                    ${key.notes ? `<div class="text-meta" style="font-size: 11px; margin-top: 4px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${esc(key.notes)}">${esc(key.notes)}</div>` : ''}
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Context</div>
                    <div style="display: flex; gap: 4px; align-items: center;">
                        <span class="badge ${key.environment === 'prod' ? 'badge-prod' : 'badge-dev'}">${esc(key.environment)}</span>
                        <span class="badge" style="background: var(--surface-2); color: var(--text-secondary); border-radius: 4px; font-size: 10px;">v${key.version || 1}</span>
                        ${(() => {
                    if (!key.expiryDate) return '';
                    const expiry = new Date(key.expiryDate);
                    const now = new Date();
                    const diffDays = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));

                    if (diffDays < 0) return '<span class="badge badge-danger" title="Key has expired and should be rotated immediately.">Expired</span>';
                    if (diffDays <= 7) return `<span class="badge badge-warning" title="Expires in ${diffDays} days. Rotation recommended.">Expiring</span>`;
                    return '';
                })()}
                    </div>
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
                <div style="text-align: right; display: flex; gap: 8px; justify-content: flex-end;">
                    <button class="btn btn-ghost" style="color: var(--primary); padding: 0.5rem;" onclick="openEditModal('${key.id}')" title="Edit Secret">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                    <button class="btn btn-ghost" style="color: var(--text-secondary); padding: 0.5rem;" onclick="openHistory('${key.id}', '${key.name}')" title="Version Timeline">
                        <i class="fa-solid fa-clock-rotate-left"></i>
                    </button>
                    <button class="btn btn-ghost" style="color: var(--error); padding: 0.5rem;" onclick="deleteKey('${key.id}')" title="Revoke Key" aria-label="Delete key">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;
            keysContainer.appendChild(item);
        });
    };

    // --- Search Logic ---
    if (keySearch) {
        keySearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = allKeys.filter(k =>
                k.name.toLowerCase().includes(query) ||
                k.service.toLowerCase().includes(query) ||
                k.environment.toLowerCase().includes(query) ||
                (k.notes && k.notes.toLowerCase().includes(query))
            );
            renderKeys(filtered);
        });
    }

    // History & Rollback Logic
    const historyModal = document.getElementById('history-modal');
    const historyContent = document.getElementById('history-content');

    if (document.getElementById('close-history-modal')) {
        document.getElementById('close-history-modal').onclick = () => historyModal.style.display = 'none';
    }

    window.openHistory = async (keyId, keyName) => {
        historyModal.style.display = 'flex';
        historyContent.innerHTML = `
            <div style="padding: 40px; text-align: center;">
                <i class="fa-solid fa-circle-notch fa-spin"></i>
                <p class="text-muted" style="margin-top: 12px;">Scanning timeline for ${esc(keyName)}...</p>
            </div>
        `;

        try {
            const history = await ApiClient.keys.getHistory(keyId);

            if (history.length === 0) {
                historyContent.innerHTML = `<div style="padding: 40px; text-align: center;" class="text-muted">No version history found.</div>`;
                return;
            }

            let html = '<div style="display: flex; flex-direction: column; gap: 12px; padding: 12px;">';
            history.forEach(v => {
                const isCurrent = v.version === allKeys.find(k => k.id === keyId)?.version;
                html += `
                    <div class="stat-card-premium" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; ${isCurrent ? 'border-left: 3px solid var(--accent-1);' : ''}">
                        <div>
                            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                                <span class="badge" style="background: var(--surface-2); color: var(--text-primary); font-weight: 700;">v${v.version}</span>
                                ${isCurrent ? '<span class="badge badge-dev" style="font-size: 10px;">Current</span>' : ''}
                                <span style="font-size: 13px; font-weight: 600; color: var(--text-main); margin-left: 8px;">${esc(v.name)} (${esc(v.service)})</span>
                                <span class="text-meta" style="font-size: 12px; margin-left: auto;">${new Date(v.createdAt).toLocaleString()}</span>
                            </div>
                            <div style="font-size: 13px; color: var(--text-secondary);">Modified by: <b>${esc(v.updatedBy)}</b></div>
                            ${v.notes ? `<div style="font-size: 11px; color: var(--text-tertiary); font-style: italic; margin-top: 2px;">"${esc(v.notes)}"</div>` : ''}
                        </div>
                        <div>
                            ${!isCurrent ? `
                                <button class="btn btn-secondary btn-sm" onclick="rollbackToVersion('${keyId}', ${v.version})">
                                    <i class="fa-solid fa-rotate-left" style="margin-right: 6px;"></i> Rollback
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
            html += '</div>';
            historyContent.innerHTML = html;
        } catch (err) {
            historyContent.innerHTML = `<div style="padding: 40px; text-align: center; color: var(--error);">${err.message}</div>`;
        }
    };

    window.rollbackToVersion = async (keyId, version) => {
        const confirmed = await notifications.confirm(
            'Confirm Rollback',
            `Are you sure you want to revert this secret to version ${version}? This will create a new v${(allKeys.find(k => k.id === keyId)?.version || 0) + 1} with the historical data.`,
            'Restore Version',
            'info'
        );

        if (!confirmed) return;

        try {
            notifications.showToast('Rollback initiated', 'Processing vault rollback sequence...', 'info');
            const updatedKey = await ApiClient.keys.rollback(keyId, version);
            console.log("[Debug] Rollback successful. Re-syncing UI.", updatedKey);

            // Sync local state immediately
            const idx = allKeys.findIndex(k => k.id === keyId);
            if (idx !== -1 && updatedKey) {
                allKeys[idx] = updatedKey;
                renderKeys(allKeys); // Force UI rebuild
                console.log("[Debug] UI manually updated to version: ", updatedKey.version);
                console.log("[Debug] New Ciphertext Hash (truncated):", updatedKey.encryptedValue.substring(0, 8));
            }

            historyModal.style.display = 'none';
            notifications.showToast('Rollback Successful', `Secret restored to state from v${version}.`, 'success');

            // Full refresh to be safe (with cache buster)
            await loadKeys();
        } catch (err) {
            notifications.showToast('Rollback Failed', err.message, 'error');
        }
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
        document.getElementById('editing-key-id').value = '';
        document.getElementById('key-modal-title').textContent = 'Security Initialization';
        keyForm.reset();
        document.getElementById('key-value').placeholder = 'Paste secret here...';
        keyModal.style.display = 'flex';
        document.getElementById('key-name').focus();
    };

    window.openEditModal = async (id) => {
        const key = allKeys.find(k => k.id === id);
        if (!key) return;

        document.getElementById('editing-key-id').value = id;
        document.getElementById('key-modal-title').textContent = 'Update Secret';
        document.getElementById('key-name').value = key.name;
        document.getElementById('key-service').value = key.service;
        document.getElementById('key-env').value = key.environment;
        document.getElementById('key-notes').value = key.notes || '';
        document.getElementById('key-expiry').value = key.expiryDate || '';

        // Update environment dropdown text
        const envItem = Array.from(envMenu.querySelectorAll('.dropdown-item')).find(i => i.getAttribute('data-value') === key.environment);
        if (envItem) {
            envSelectedText.textContent = envItem.textContent.trim();
            envMenu.querySelectorAll('.dropdown-item').forEach(i => i.classList.remove('selected'));
            envItem.classList.add('selected');
        }

        // Update expiry text
        if (key.expiryDate) {
            selectedText.textContent = new Date(key.expiryDate).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
        } else {
            selectedText.textContent = 'No Expiration Set';
        }

        // We don't fill the sensitive value - user must re-enter it or we leave it empty to indicate "no change"
        // For security, it's better to force them to re-enter it if they want to change it.
        document.getElementById('key-value').value = '';
        document.getElementById('key-value').placeholder = 'Enter new value (Leave empty to keep current)';

        keyModal.style.display = 'flex';
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
        const editingId = document.getElementById('editing-key-id').value;

        try {
            let ciphertext = null;
            let iv = null;

            if (rawValue) {
                // Encryption only if value changed
                let cryptoKey = await CryptoModule.getProjectKey(projectId);
                if (!cryptoKey) {
                    notifications.showToast('Security Error', 'Failed to initialize project security vault.', 'error');
                    return;
                }
                const result = await CryptoModule.encrypt(rawValue, cryptoKey);
                ciphertext = result.ciphertext;
                iv = result.iv;
            } else if (editingId) {
                // If editing and no new value, keep current
                const currentKey = allKeys.find(k => k.id === editingId);
                ciphertext = currentKey.encryptedValue;
                iv = currentKey.iv;
            } else {
                notifications.showToast('Validation Error', 'Secret value is required for new entries.', 'error');
                return;
            }

            if (editingId) {
                await ApiClient.keys.update(editingId, {
                    projectId,
                    name,
                    service,
                    environment: env,
                    encryptedValue: ciphertext,
                    iv: iv,
                    expiryDate: expiry,
                    notes
                });
                notifications.showToast('Key Updated', `Modifications to "${name}" persisted as new version.`, 'success');
            } else {
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
                notifications.showToast('Key Provisioned', `Secret for "${name}" added to vault.`, 'success');
            }
            keyModal.style.display = 'none';
            keyForm.reset();
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
        console.log(`[Vault] Reveal Action for ID: ${id}`);
        console.log(`[Vault] Data being revealed (prefix): ${ciphertext.substring(0, 10)}`);

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

