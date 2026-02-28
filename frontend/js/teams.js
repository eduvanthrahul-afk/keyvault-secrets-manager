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
    const userEmailDisplay = document.getElementById('user-email-display');
    const currentUserEmail = (localStorage.getItem('user_email') || '').toLowerCase();

    if (userEmailDisplay) userEmailDisplay.textContent = localStorage.getItem('user_email');

    // Auth check
    if (!localStorage.getItem('jwt_token')) {
        window.location.href = 'login.html';
        return;
    }

    const loadProjects = async () => {
        try {
            const projects = await ApiClient.projects.getAll();
            projectSelector.innerHTML = '<option value="">Select a workspace...</option>';
            projects.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.id;
                opt.textContent = p.name;
                projectSelector.appendChild(opt);
            });
        } catch (err) {
            console.error('Failed to load projects:', err);
        }
    };

    const loadMembers = async (projectId) => {
        if (!projectId) {
            membersSection.style.display = 'none';
            emptyState.style.display = 'block';
            addMemberBtn.style.display = 'none';
            return;
        }

        try {
            const members = await ApiClient.projects.getMembers(projectId) || [];

            // Case-insensitive role check with null safety
            const me = members.find(m => m.email && m.email.toLowerCase() === currentUserEmail);
            const isOwner = me && me.role && me.role.toUpperCase() === 'OWNER';

            if (isOwner) {
                addMemberBtn.style.display = 'flex';
            } else {
                addMemberBtn.style.display = 'none';
            }

            renderMembers(members, isOwner);
            membersSection.style.display = 'block';
            emptyState.style.display = 'none';
        } catch (err) {
            console.error('Failed to load members:', err);
            membersSection.style.display = 'none';
            emptyState.style.display = 'block';
            addMemberBtn.style.display = 'none';
        }
    };

    const renderMembers = (members, isOwner) => {
        membersList.innerHTML = '';
        members.forEach(m => {
            const isSelf = m.email.toLowerCase() === currentUserEmail;
            const item = document.createElement('div');
            item.className = 'key-item';
            item.style.gridTemplateColumns = '2fr 1fr auto';
            item.innerHTML = `
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Member Email</div>
                    <div style="font-weight: 600; color: var(--text-main);">${m.email} ${isSelf ? '<span style="color: var(--primary); font-size: 0.7rem; font-weight: 500;">(You)</span>' : ''}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; font-weight: 700; color: var(--text-tertiary); text-transform: uppercase; margin-bottom: 0.25rem;">Role</div>
                    <span class="badge ${(m.role || '').toUpperCase() === 'OWNER' ? 'badge-prod' : 'badge-dev'}">${m.role || 'MEMBER'}</span>
                </div>
                <div style="text-align: right;">
                    ${(isOwner && (m.role || '').toUpperCase() !== 'OWNER' && !isSelf) ? `
                        <button class="btn btn-ghost remove-member-btn" data-email="${m.email}" style="color: var(--error); padding: 0.5rem;" title="Remove Member">
                            <i class="fa-solid fa-user-minus"></i>
                        </button>
                    ` : ''}
                </div>
            `;
            membersList.appendChild(item);
        });

        // Add event listeners for removal
        if (isOwner) {
            document.querySelectorAll('.remove-member-btn').forEach(btn => {
                btn.onclick = async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const email = btn.getAttribute('data-email');
                    if (!email) return;

                    if (confirm(`Are you sure you want to remove member ${email}?`)) {
                        try {
                            const projectId = projectSelector.value;
                            console.log(`Attempting to remove member ${email} from project ${projectId}`);
                            await ApiClient.projects.removeMember(projectId, email);
                            console.log('Member removed successfully');
                            await loadMembers(projectId); // Reload list
                        } catch (err) {
                            console.error('Removal Error:', err);
                            alert('Failed to remove member: ' + err.message);
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
        const email = document.getElementById('invite-email').value;

        try {
            await ApiClient.projects.addMember(projectId, email);
            inviteModal.style.display = 'none';
            inviteForm.reset();
            loadMembers(projectId);
        } catch (err) {
            alert(err.message);
        }
    };

    await loadProjects();

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.onclick = async () => {
            localStorage.clear();
            sessionStorage.clear();
            await CryptoModule.clearSessionVault();
            window.location.href = 'login.html';
        };
    }
});
