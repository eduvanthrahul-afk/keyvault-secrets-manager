document.addEventListener('DOMContentLoaded', async () => {
    const projectSelector = document.getElementById('project-selector');
    const logsSection = document.getElementById('logs-section');
    const emptyState = document.getElementById('empty-state');
    const logsTableBody = document.getElementById('logs-table-body');
    const projectTitleDisplay = document.getElementById('project-title-display');

    // Auth check
    if (!localStorage.getItem('jwt_token')) {
        window.location.href = 'login.html';
        return;
    }

    const loadProjects = async () => {
        try {
            const projects = await ApiClient.projects.getAll();
            const menu = document.getElementById('dropdown-menu');
            const toggle = document.getElementById('dropdown-toggle');
            const selectedText = document.getElementById('dropdown-selected-text');
            const hiddenInput = document.getElementById('project-selector');

            menu.innerHTML = '';

            // Default "Observation" state
            const defaultItem = document.createElement('div');
            defaultItem.className = 'dropdown-item';
            defaultItem.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>Observe Context...</span>`;
            defaultItem.onclick = () => {
                selectProject('', 'Observe Context...', 'Registry', hiddenInput, selectedText, menu, toggle);
            };
            menu.appendChild(defaultItem);

            projects.forEach(p => {
                const item = document.createElement('div');
                item.className = 'dropdown-item';
                item.innerHTML = `<i class="fa-solid fa-folder-closed"></i> <span>${p.name}</span>`;
                item.onclick = () => {
                    selectProject(p.id, p.name, p.name, hiddenInput, selectedText, menu, toggle);
                };
                menu.appendChild(item);
            });

            toggle.onclick = (e) => {
                e.stopPropagation();
                const isOpen = menu.classList.contains('show');
                closeAllDropdowns();
                if (!isOpen) {
                    menu.classList.add('show');
                    toggle.classList.add('active');
                }
            };

            document.addEventListener('click', () => closeAllDropdowns());

        } catch (err) {
            console.error('Failed to load projects:', err);
        }
    };

    const closeAllDropdowns = () => {
        document.querySelectorAll('.dropdown-menu').forEach(m => m.classList.remove('show'));
        document.querySelectorAll('.dropdown-toggle').forEach(t => t.classList.remove('active'));
    };

    const selectProject = (id, name, displayTitle, input, textElem, menu, toggle) => {
        input.value = id;
        textElem.textContent = name;
        projectTitleDisplay.textContent = displayTitle;
        menu.classList.remove('show');
        toggle.classList.remove('active');
        loadLogs(id);
    };

    const loadLogs = async (projectId) => {
        if (!projectId) {
            logsSection.style.display = 'none';
            emptyState.style.display = 'block';
            document.getElementById('empty-state-title').textContent = "Awaiting Forensic Context";
            document.getElementById('empty-state-desc').textContent = "Select a workspace context from the registry above to monitor the security event timeline.";
            return;
        }

        try {
            const logs = await ApiClient.projects.getAuditLogs(projectId) || [];
            renderLogs(logs);
            logsSection.style.display = 'block';
            emptyState.style.display = 'none';
        } catch (err) {
            console.error('Failed to load logs:', err);
            logsSection.style.display = 'none';
            emptyState.style.display = 'block';
            document.getElementById('empty-state-title').textContent = "Access Denied";
            document.getElementById('empty-state-desc').textContent = "You do not have the required permissions to view audit logs for this project.";
        }
    };

    const getActionBadge = (action) => {
        const a = action.toUpperCase();
        if (a.includes('DELETE') || a.includes('REMOVE') || a.includes('REVOKE') || a.includes('PURGE') || a.includes('DROP')) return 'badge-danger';
        if (a.includes('CREATE') || a.includes('ADD') || a.includes('INVITE') || a.includes('PROVISION')) return 'badge-success';
        if (a.includes('UPDATE') || a.includes('EDIT') || a.includes('CHANGE') || a.includes('ROTATE')) return 'badge-warning';
        if (a.includes('VIEW') || a.includes('LIST') || a.includes('GET') || a.includes('DECRYPT')) return 'badge-info';
        if (a.includes('LOGIN') || a.includes('AUTH') || a.includes('ACCESS')) return 'badge-prod';
        return 'badge-dev';
    };

    const renderLogs = (logs) => {
        logsTableBody.innerHTML = '';
        if (logs.length === 0) {
            logsTableBody.innerHTML = `
                <tr>
                    <td colspan="5" style="padding: 48px; text-align: center; color: var(--text-muted);">
                        <div style="margin-bottom: 12px; opacity: 0.5;"><i class="fa-solid fa-inbox" style="font-size: 24px;"></i></div>
                        No forensic logs found for this workspace context.
                    </td>
                </tr>
            `;
            return;
        }

        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-soft)';

            const date = new Date(log.createdAt).toLocaleString();

            tr.innerHTML = `
                <td style="padding: 1rem; color: var(--text-secondary); white-space: nowrap;">${date}</td>
                <td style="padding: 1rem; color: var(--text-primary); font-weight: 600;">${log.userEmail}</td>
                <td style="padding: 1rem;"><span class="badge ${getActionBadge(log.action)}">${log.action}</span></td>
                <td style="padding: 1rem;"><span class="mono-token" style="font-size: 11px; opacity: 0.8;">${log.ipAddress}</span></td>
                <td style="padding: 1rem; color: var(--text-secondary);">${log.details}</td>
            `;
            logsTableBody.appendChild(tr);
        });
    };

    const refreshLogsBtn = document.getElementById('refresh-logs-btn');
    if (refreshLogsBtn) refreshLogsBtn.onclick = () => loadLogs(projectSelector.value);

    await loadProjects();
});
