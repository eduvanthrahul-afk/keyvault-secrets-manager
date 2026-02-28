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
    if (!localStorage.getItem('jwt_token')) {
        window.location.href = 'login.html';
        return;
    }

    const loadProjects = async () => {
        try {
            allProjects = await ApiClient.projects.getAll();
            renderProjects(allProjects);
            updateStats(allProjects);
        } catch (err) {
            console.error(err);
            projectList.innerHTML = `
                <div style="grid-column: 1/-1; padding: 4rem; text-align: center; border: 1px solid var(--error-border); background: var(--error-bg); border-radius: var(--radius-xl);">
                    <div style="font-size: 2rem; margin-bottom: 1rem; color: var(--error);">⚠️</div>
                    <h3 style="margin-bottom: 0.5rem; color: var(--error);">Failed to load projects</h3>
                    <p class="text-muted">${err.message}</p>
                    <button class="btn btn-ghost" onclick="window.location.reload()" style="margin-top: 1rem;">Try again</button>
                </div>
            `;
        }
    };

    const updateStats = async (projects) => {
        const statProjects = document.getElementById('stat-projects');
        const statKeys = document.getElementById('stat-keys');
        const statExpiring = document.getElementById('stat-expiring');

        if (statProjects) statProjects.textContent = projects.length;

        // Fetch all keys to count them
        try {
            let totalKeys = 0;
            let totalExpiring = 0;
            const now = new Date();
            const nextWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

            for (const project of projects) {
                const keys = await ApiClient.keys.getByProject(project.id);
                totalKeys += keys.length;

                // Count expiring
                keys.forEach(k => {
                    if (k.expiryDate) {
                        const expiry = new Date(k.expiryDate);
                        if (expiry > now && expiry < nextWeek) totalExpiring++;
                    }
                });
            }

            if (statKeys) statKeys.textContent = totalKeys;
            if (statExpiring) statExpiring.textContent = totalExpiring;
        } catch (err) {
            console.error("Failed to load key counts", err);
        }
    };

    window.deleteProject = async (id, name, event) => {
        if (event) event.stopPropagation();
        if (!confirm(`Are you sure you want to delete the project "${name}" and all its API keys? This action cannot be undone.`)) {
            return;
        }

        try {
            await ApiClient.projects.delete(id);
            loadProjects();
        } catch (err) {
            alert('Failed to delete project: ' + err.message);
        }
    };

    const renderProjects = (projects) => {
        projectList.innerHTML = '';
        if (projects.length === 0) {
            projectList.innerHTML = `
                <div style="grid-column: 1/-1; padding: 4rem; text-align: center; border: 1px dashed var(--border-base); border-radius: var(--radius-xl); opacity: 0.6;">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">📁</div>
                    <h3 style="margin-bottom: 0.5rem;">${projectSearch && projectSearch.value ? 'No matching projects' : 'No active projects'}</h3>
                    <p class="text-muted">${projectSearch && projectSearch.value ? 'Try a different search term.' : 'Create your first project to begin securing API keys.'}</p>
                </div>
            `;
            return;
        }

        projects.forEach(project => {
            const card = document.createElement('div');
            card.className = 'card';
            card.setAttribute('role', 'button');
            card.setAttribute('tabindex', '0');
            card.setAttribute('aria-label', `Project: ${project.name}`);

            card.onclick = () => {
                sessionStorage.setItem('current_project', JSON.stringify(project));
                window.location.href = `project.html?id=${project.id}`;
            };
            card.onkeypress = (e) => { if (e.key === 'Enter') card.onclick(); };

            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem;">
                    <div style="width: 40px; height: 40px; background: var(--bg-muted); border-radius: 8px; display: flex; align-items: center; justify-content: center; border: 1px solid var(--border-base);">
                        <i class="fa-solid fa-folder-closed" style="color: var(--text-secondary);"></i>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        <span class="badge ${project.tag?.toLowerCase() === 'prod' || project.tag?.toLowerCase() === 'production' ? 'badge-prod' : 'badge-dev'}">${project.tag || 'Unset'}</span>
                        <button class="btn btn-ghost" onclick="deleteProject('${project.id}', '${project.name}', event)" style="padding: 0.25rem 0.5rem; color: var(--error);" title="Delete Project">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                </div>
                <h3>${project.name}</h3>
                <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-base); display: flex; align-items: center; justify-content: space-between; font-size: 0.75rem; color: var(--text-secondary);">
                    <span>Security Vault</span>
                    <i class="fa-solid fa-arrow-right"></i>
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
            await ApiClient.projects.create({ name, tag });
            projectModal.style.display = 'none';
            projectForm.reset();
            loadProjects();
        } catch (err) {
            alert('Failed to create project: ' + err.message);
        }
    };

    loadProjects();
});

