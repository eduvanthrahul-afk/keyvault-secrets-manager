// dashboard.js
document.addEventListener('DOMContentLoaded', async () => {
    const projectList = document.getElementById('project-list');
    const newProjectBtn = document.getElementById('new-project-btn');
    const projectModal = document.getElementById('project-modal');
    const projectForm = document.getElementById('project-form');
    const closeModal = document.getElementById('close-modal');
    const cancelProject = document.getElementById('cancel-project');
    const userEmailDisplay = document.getElementById('user-email-display');
    const projectSearch = document.getElementById('project-search');

    let allProjects = [];

    if (userEmailDisplay) userEmailDisplay.textContent = localStorage.getItem('user_email');

    // Check auth
    if (!localStorage.getItem('user_email')) {
        window.location.href = 'login.html';
        return;
    }

    const loadProjects = async () => {
        try {
            // Telemetry Loading State
            projectList.innerHTML = Array(3).fill(0).map(() => `
                <div class="bento-card w-4 skeleton-card" style="position: relative; overflow: hidden; background: var(--surface-1); border: 1px solid var(--border);">
                     <div class="scan-line" style="position: absolute; inset: 0; background: linear-gradient(to bottom, transparent, rgba(129, 140, 248, 0.1), transparent); height: 100%; width: 100%; filter: blur(20px); animation: scanLineMove 2s infinite linear; pointer-events: none;"></div>
                     <div style="opacity: 0.5;">
                         <div class="skeleton-text" style="width: 40%; background: var(--surface-3); height: 12px; border-radius: 4px; margin-bottom: 24px;"></div>
                         <div class="skeleton-text" style="width: 80%; background: var(--surface-2); height: 24px; border-radius: 6px; margin-bottom: 12px;"></div>
                         <div class="skeleton-text" style="width: 60%; background: var(--surface-2); height: 10px; border-radius: 4px;"></div>
                     </div>
                </div>
            `).join('');

            allProjects = await ApiClient.projects.getAll();
            if (!allProjects) return; // Authentication expiration handled by ApiClient

            renderProjects(allProjects);
            updateStats(allProjects);

            const welcomeCount = document.getElementById('welcome-project-count');
            if (welcomeCount) welcomeCount.textContent = allProjects.length;
        } catch (err) {
            console.error(err);
            projectList.innerHTML = `
                <div style="grid-column: 1/-1; padding: 4rem; text-align: center; border: 1px solid var(--error-border); background: var(--error-bg); border-radius: 24px;">
                    <div style="font-size: 2.5rem; margin-bottom: 1.5rem; color: var(--error);">⚠️</div>
                    <h3 style="margin-bottom: 0.5rem; color: var(--error); font-weight: 700;">Registry Synchronization Failed</h3>
                    <p class="text-muted" style="max-width: 400px; margin: 0 auto;">${err.message}</p>
                    <button class="btn btn-primary" onclick="window.location.reload()" style="margin-top: 1.5rem;">Re-establish Connection</button>
                </div>
            `;
        }
    };

    const updateStats = (projects) => {
        const statProjects = document.getElementById('stat-projects');
        const statKeys = document.getElementById('stat-keys');
        const statExpiring = document.getElementById('stat-expiring');

        if (statProjects) statProjects.textContent = projects.length;

        const totals = projects.reduce((acc, p) => {
            acc.keys += (p.keyCount || 0);
            acc.expiring += (p.expiringKeyCount || 0);
            return acc;
        }, { keys: 0, expiring: 0 });

        if (statKeys) statKeys.textContent = totals.keys;
        if (statExpiring) statExpiring.textContent = totals.expiring;
    };

    window.deleteProject = async (id, name, event) => {
        if (event) event.stopPropagation();

        const confirmed = await notifications.confirm(
            'Purge Security Context',
            `Are you sure you want to delete the workspace "${name}"? This will permanently revoke all associated API keys and credentials.`,
            'Confirm Purge'
        );

        if (!confirmed) return;

        try {
            await ApiClient.projects.delete(id);
            notifications.showToast('Workspace Purged', `The context "${esc(name)}" has been removed from the registry.`, 'success');
            loadProjects();
        } catch (err) {
            notifications.showToast('Purge Failed', esc(err.message), 'error');
        }
    };


    const renderProjects = (projects) => {
        projectList.innerHTML = '';
        if (projects.length === 0) {
            projectList.innerHTML = `
                <div style="grid-column: 1/-1; padding: 6rem 24px; text-align: center; border: 1px dashed var(--border); border-radius: 24px; background: var(--surface-1);">
                    <div style="font-size: 3rem; margin-bottom: 1.5rem; opacity: 0.5;">📂</div>
                    <h3 style="margin-bottom: 0.5rem; font-weight: 700;">${(projectSearch && projectSearch.value) ? 'No Matching Contexts' : 'Registry Empty'}</h3>
                    <p class="text-muted" style="max-width: 320px; margin: 0 auto;">${(projectSearch && projectSearch.value) ? `No workspace matches the term "${esc(projectSearch.value)}" in the secure registry.` : 'Initialize your first security context to begin managing encrypted API keys.'}</p>
                </div>
            `;
            return;
        }

        projects.forEach(project => {
            const card = document.createElement('div');
            card.className = 'bento-card w-4 project-card-premium';

            const tag = (project.tag || 'Unset').toLowerCase();
            const isProd = tag === 'prod' || tag === 'production';
            const currentUserEmail = (localStorage.getItem('user_email') || '').toLowerCase().trim();
            const projectOwnerEmail = (project.ownerEmail || '').toLowerCase().trim();
            const isOwner = projectOwnerEmail === currentUserEmail;

            card.onclick = () => {
                sessionStorage.setItem('current_project', JSON.stringify(project));
                window.location.href = `project.html?id=${project.id}`;
            };

            card.innerHTML = `
                <div class="top-bar">
                    <div class="project-icon-square">
                        <i class="fa-solid fa-folder-closed"></i>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="project-tag-pill ${isProd ? 'badge-prod' : 'badge-dev'}">${esc(tag)}</span>
                        ${isOwner ? `
                        <button class="btn btn-ghost" onclick="deleteProject('${project.id}', '${esc(project.name.replace(/'/g, "\\'"))}', event)" style="width: 32px; height: 32px; padding: 0; color: var(--error); border-radius: 8px;" title="Purge Context">
                            <i class="fa-solid fa-trash-can" style="font-size: 13px;"></i>
                        </button>
                        ` : ''}
                    </div>
                </div>
                <div class="body">
                    <h3 class="project-name-h3">${esc(project.name)}</h3>
                    <p class="text-meta" style="line-height: 1.4;">Active security vault containing managed secret keys and team access policies.</p>
                </div>
                <div class="footer">
                    <span>Manage Keys & Access</span>
                    <i class="fa-solid fa-chevron-right" style="font-size: 10px; opacity: 0.5;"></i>
                </div>
            `;
            projectList.appendChild(card);
        });
    };

    if (projectSearch) {
        projectSearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = allProjects.filter(p =>
                p.name.toLowerCase().includes(query) ||
                (p.tag && p.tag.toLowerCase().includes(query))
            );
            renderProjects(filtered);
        });
    }

    newProjectBtn.onclick = () => projectModal.style.display = 'flex';
    closeModal.onclick = () => projectModal.style.display = 'none';
    cancelProject.onclick = () => projectModal.style.display = 'none';

    projectForm.onsubmit = async (e) => {
        e.preventDefault();
        const name = document.getElementById('project-name').value;
        const tag = document.getElementById('project-tag').value;

        try {
            const rsaPublicKeyHex = sessionStorage.getItem('public_key') || localStorage.getItem('public_key');
            if (!rsaPublicKeyHex) {
                throw new Error("Missing secure identity. Please re-login to restore your encryption keys.");
            }

            const rsaPublicKey = await CryptoModule.importPublicKey(rsaPublicKeyHex);
            const projectKey = await CryptoModule.generateProjectKey();
            const encryptedProjectKey = await CryptoModule.wrapProjectKey(projectKey, rsaPublicKey);

            await ApiClient.projects.create({ name, tag, encryptedProjectKey });
            projectModal.style.display = 'none';
            projectForm.reset();
            notifications.showToast('Workspace Created', `Successfully initialized context "${name}".`, 'success');
            loadProjects();
        } catch (err) {
            notifications.showToast('Creation Failed', err.message, 'error');
        }
    };


    loadProjects();
});

