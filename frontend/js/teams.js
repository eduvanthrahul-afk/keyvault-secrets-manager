document.addEventListener('DOMContentLoaded', async () => {
    const projectSelector = document.getElementById('project-selector');
    const membersSection = document.getElementById('members-section');
    const emptyState = document.getElementById('empty-state');
    const membersList = document.getElementById('members-list');
    const addMemberBtn = document.getElementById('add-member-btn');
    const inviteModal = document.getElementById('invite-modal');
    const inviteForm = document.getElementById('invite-form');
    const closeInviteModal = document.getElementById('close-invite-modal');
    const cancelInvite = document.getElementById('cancel-invite');
    const currentUserEmail = (localStorage.getItem('user_email') || '').toLowerCase();

    // Auth check
    if (!localStorage.getItem('user_email')) {
        window.location.href = 'login.html';
        return;
    }

    let currentMembers = [];

    const loadProjects = async () => {
        try {
            const projects = await ApiClient.projects.getAll();
            if (!projects) return;

            const menu = document.getElementById('dropdown-menu');
            const toggle = document.getElementById('dropdown-toggle');
            const selectedText = document.getElementById('dropdown-selected-text');
            const hiddenInput = document.getElementById('project-selector');

            menu.innerHTML = '';

            // Add "Select Architecture" as first item
            const defaultItem = document.createElement('div');
            defaultItem.className = 'dropdown-item';
            defaultItem.innerHTML = `<i class="fa-solid fa-cube"></i> <span>Select Architecture...</span>`;
            defaultItem.onclick = () => {
                selectProject('', 'Select Architecture...', hiddenInput, selectedText, menu, toggle);
            };
            menu.appendChild(defaultItem);

            projects.forEach(p => {
                const item = document.createElement('div');
                item.className = 'dropdown-item';
                item.innerHTML = `<i class="fa-solid fa-folder-closed"></i> <span>${esc(p.name)}</span>`;
                item.onclick = () => {
                    selectProject(p.id, p.name, hiddenInput, selectedText, menu, toggle);
                };
                menu.appendChild(item);
            });

            // Toggle logic
            toggle.onclick = (e) => {
                e.stopPropagation();
                const isOpen = menu.classList.contains('show');
                closeAllDropdowns();
                if (!isOpen) {
                    menu.classList.add('show');
                    toggle.classList.add('active');
                }
            };

            // Global close
            document.addEventListener('click', () => closeAllDropdowns());

        } catch (err) {
            console.error('Failed to load projects:', err);
        }
    };

    const closeAllDropdowns = () => {
        document.querySelectorAll('.dropdown-menu').forEach(m => m.classList.remove('show'));
        document.querySelectorAll('.dropdown-toggle').forEach(t => t.classList.remove('active'));
    };

    const selectProject = (id, name, input, textElem, menu, toggle) => {
        input.value = id;
        textElem.textContent = name;
        menu.classList.remove('show');
        toggle.classList.remove('active');
        loadMembers(id, name);
    };

    const loadMembers = async (projectId, projectName) => {
        if (!projectId) {
            membersSection.style.display = 'none';
            emptyState.style.display = 'block';
            addMemberBtn.style.display = 'none';
            document.getElementById('search-container').style.display = 'none';
            document.getElementById('project-title-display').textContent = 'Registry';
            return;
        }

        try {
            document.getElementById('project-title-display').textContent = projectName;
            document.getElementById('search-container').style.display = 'block';

            currentMembers = await ApiClient.projects.getMembers(projectId) || [];

            const me = currentMembers.find(m => m.email && m.email.toLowerCase() === currentUserEmail);
            const myRole = me && me.role ? me.role.toUpperCase() : 'VIEWER';
            const canManageMembers = ['ADMIN', 'OWNER'].includes(myRole);

            if (canManageMembers) {
                addMemberBtn.style.display = 'flex';
            } else {
                addMemberBtn.style.display = 'none';
            }

            renderMembers(currentMembers, canManageMembers, myRole);
            membersSection.style.display = 'block';
            emptyState.style.display = 'none';
        } catch (err) {
            console.error('Failed to load members:', err);
            membersSection.style.display = 'none';
            emptyState.style.display = 'block';
            addMemberBtn.style.display = 'none';
            document.getElementById('search-container').style.display = 'none';
        }
    };

    const renderMembers = (members, canManageMembers, myRole) => {
        membersList.innerHTML = '';

        // Update Stats
        const totalCount = members.length;
        const adminCount = members.filter(m => ['ADMIN', 'OWNER'].includes((m.role || '').toUpperCase())).length;
        const uniqueRoles = new Set(members.map(m => (m.role || 'VIEWER').toUpperCase())).size;

        const statTotal = document.getElementById('stat-total-members');
        const statAdmins = document.getElementById('stat-admins');
        const statRoles = document.getElementById('stat-roles');

        if (statTotal) statTotal.textContent = totalCount;
        if (statAdmins) statAdmins.textContent = adminCount;
        if (statRoles) statRoles.textContent = uniqueRoles;

        if (members.length === 0) {
            membersList.innerHTML = '<div style="padding: 4rem; text-align: center; color: var(--text-muted); grid-column: 1/-1;">No members found in this workspace registry.</div>';
            return;
        }

        members.forEach(m => {
            const isSelf = m.email.toLowerCase() === currentUserEmail;
            const targetRole = (m.role || '').toUpperCase();
            const initial = m.email.charAt(0).toUpperCase();

            const card = document.createElement('div');
            card.className = 'member-card';

            const canEditRole = canManageMembers && !isSelf && targetRole !== 'OWNER' && !(targetRole === 'ADMIN' && myRole !== 'OWNER');

            let roleControl = '';
            if (canEditRole) {
                const isAdminOptionDisabled = (myRole !== 'OWNER') ? 'disabled' : '';
                roleControl = `
                    <select class="select role-select" data-email="${esc(m.email)}" style="padding: 4px 8px; font-size: 12px; width: auto; height: 32px; border-radius: 8px;">
                        <option value="VIEWER" ${targetRole === 'VIEWER' ? 'selected' : ''}>Viewer</option>
                        <option value="EDITOR" ${targetRole === 'EDITOR' ? 'selected' : ''}>Editor</option>
                        <option value="ADMIN" ${targetRole === 'ADMIN' ? 'selected' : ''} ${isAdminOptionDisabled}>Admin</option>
                    </select>
                `;
            } else {
                roleControl = `<span class="role-badge-pill ${targetRole.toLowerCase()}">${esc(targetRole)}</span>`;
            }

            const canRemove = canManageMembers && targetRole !== 'OWNER' && !isSelf && !(targetRole === 'ADMIN' && myRole !== 'OWNER');

            card.innerHTML = `
                <div class="member-header">
                    <div class="member-avatar">${esc(initial)}</div>
                    <div class="member-info">
                        <span class="member-email" title="${esc(m.email)}">${esc(m.email)}</span>
                        <div class="member-status">
                            <span class="status-indicator green" style="width: 6px; height: 6px; margin: 0;"></span>
                            <span>${isSelf ? 'You (Current Session)' : 'Active Workspace Member'}</span>
                        </div>
                    </div>
                </div>
                <div class="member-footer">
                    <div>${roleControl}</div>
                    <div class="member-actions">
                        ${canRemove ? `
                            <button class="action-btn-mini danger remove-member-btn" data-email="${esc(m.email)}" title="Revoke Membership">
                                <i class="fa-solid fa-user-xmark"></i>
                            </button>
                        ` : `
                            <div class="action-btn-mini" style="opacity: 0.3; cursor: not-allowed;" title="Permission Locked">
                                <i class="fa-solid fa-lock"></i>
                            </div>
                        `}
                    </div>
                </div>
            `;
            membersList.appendChild(card);
        });

        // Add event listeners for removal and role change
        if (canManageMembers) {
            document.querySelectorAll('.role-select').forEach(select => {
                select.onchange = async (e) => {
                    const email = select.getAttribute('data-email');
                    const newRole = select.value;
                    try {
                        const projectId = projectSelector.value;
                        select.disabled = true;
                        await ApiClient.projects.updateMemberRole(projectId, email, newRole);
                        notifications.showToast('Policy Updated', `Access level for ${email} modified to ${newRole}.`, 'success');
                    } catch (err) {
                        notifications.showToast('Update Failed', err.message, 'error');
                        await loadMembers(projectSelector.value); // reset visual state
                    } finally {
                        select.disabled = false;
                    }
                };
            });

            document.querySelectorAll('.remove-member-btn').forEach(btn => {
                btn.onclick = async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const email = btn.getAttribute('data-email');
                    if (!email) return;

                    const confirmed = await notifications.confirm(
                        'Revoke Membership',
                        `Are you sure you want to remove ${email} from this workspace architecture? They will lose all cryptographic access.`,
                        'Revoke Access'
                    );

                    if (confirmed) {
                        try {
                            const projectId = projectSelector.value;
                            await ApiClient.projects.removeMember(projectId, email);
                            notifications.showToast('Access Revoked', `User ${email} removed from registry.`, 'success');
                            await loadMembers(projectId);
                        } catch (err) {
                            notifications.showToast('Revocation Failed', err.message, 'error');
                        }
                    }
                };
            });
        }
    };

    projectSelector.onchange = (e) => loadMembers(e.target.value);

    addMemberBtn.onclick = () => inviteModal.style.display = 'flex';
    closeInviteModal.onclick = () => inviteModal.style.display = 'none';
    cancelInvite.onclick = () => inviteModal.style.display = 'none';

    inviteForm.onsubmit = async (e) => {
        e.preventDefault();
        const projectId = projectSelector.value;
        const email = document.getElementById('invite-email').value.trim();
        const role = document.getElementById('invite-role').value;

        try {
            // True Zero-Knowledge Access Sharing
            const keyResponse = await ApiClient.projects.getPublicKey(projectId, email);
            if (!keyResponse || !keyResponse.publicKey) {
                throw new Error("Target user hasn't generated a Zero-Knowledge Identity. Ask them to register first.");
            }

            const rsaPublicKey = await CryptoModule.importPublicKey(keyResponse.publicKey);

            // Decrypt our own master AES project key first
            const me = currentMembers.find(m => m.email && m.email.toLowerCase() === currentUserEmail);
            const myEncKey = me ? me.encryptedProjectKey : null;
            const projectKey = await CryptoModule.getProjectKey(projectId, myEncKey);

            // Re-encrypt it with the target user's public key
            const targetEncryptedProjectKey = await CryptoModule.wrapProjectKey(projectKey, rsaPublicKey);

            await ApiClient.projects.addMember(projectId, email, role, targetEncryptedProjectKey);

            inviteModal.style.display = 'none';
            inviteForm.reset();
            notifications.showToast('Invite Dispatched', `Security credentials initialized for ${esc(email)}.`, 'success');
            loadMembers(projectId, projectName);
        } catch (err) {
            notifications.showToast('Dispatch Failed', esc(err.message), 'error');
        }
    };


    document.getElementById('member-search').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        const filtered = currentMembers.filter(m =>
            m.email.toLowerCase().includes(query) ||
            (m.role || '').toLowerCase().includes(query)
        );

        const me = currentMembers.find(m => m.email && m.email.toLowerCase() === currentUserEmail);
        const myRole = me && me.role ? me.role.toUpperCase() : 'VIEWER';
        const canManageMembers = ['ADMIN', 'OWNER'].includes(myRole);

        renderMembers(filtered, canManageMembers, myRole);
    });

    await loadProjects();
});
