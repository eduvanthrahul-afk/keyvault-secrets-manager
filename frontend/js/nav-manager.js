// NavManager: Unified Navigation & Global Notifications Orchestrator
document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Notification UI
    const navRight = document.querySelector('.top-nav > div:last-child');
    const bellWrap = document.querySelector('.nav-notification-wrap');

    if (bellWrap) {
        // Build the panel
        const panel = document.createElement('div');
        panel.className = 'notification-panel';
        panel.id = 'global-notification-panel';
        panel.innerHTML = `
            <div class="notification-header">
                <h3>Priority Alerts</h3>
                <span class="badge badge-info" id="notif-count-badge">0</span>
            </div>
            <div class="notification-list" id="global-notification-list">
                <!-- Notifications injected here -->
            </div>
            <div class="notification-footer">
                <button class="btn btn-ghost" style="width: 100%; font-size: 11px;">Clear All Security Alerts</button>
            </div>
        `;
        bellWrap.appendChild(panel);

        const bellBtn = bellWrap.querySelector('button');
        const dot = bellWrap.querySelector('.notification-dot');

        if (bellBtn) {
            bellBtn.onclick = (e) => {
                e.stopPropagation();
                panel.classList.toggle('show');
                if (panel.classList.contains('show')) {
                    loadGlobalNotifications();
                }
            };
        }

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!bellWrap.contains(e.target)) {
                panel.classList.remove('show');
            }
        });

        // Background Check for Priority Notifications (Optimized)
        const checkNotifications = async () => {
            // Optimization: Only poll if the tab is visible to the user
            if (document.visibilityState !== 'visible') return;

            try {
                const summary = await ApiClient.projects.getNotificationSummary();
                if (!summary) return;

                if (summary && summary.expiringCount > 0) {
                    dot.style.display = 'block';
                    document.getElementById('notif-count-badge').textContent = summary.expiringCount;
                    document.getElementById('notif-count-badge').style.display = 'inline-flex';
                } else {
                    dot.style.display = 'none';
                    document.getElementById('notif-count-badge').style.display = 'none';
                }
            } catch (err) {
                console.warn("[NavManager] Silent health check throttled", err);
            }
        };

        const loadGlobalNotifications = async () => {
            const list = document.getElementById('global-notification-list');
            list.innerHTML = `
                <div class="notification-empty">
                    <div class="t-spinner" style="width: 20px; height: 20px; border-width: 2px; margin: 0 auto 12px;"></div>
                    Scanning Vault...
                </div>
            `;

            try {
                // For the detailed panel view, we still fetch full data to provide context
                const projects = await ApiClient.projects.getAll();
                if (!projects) return;

                const expiringProjects = projects.filter(p => p.expiringKeyCount > 0);

                if (expiringProjects.length === 0) {
                    list.innerHTML = `
                        <div class="notification-empty">
                            <i class="fa-solid fa-shield-check" style="color: var(--success); opacity: 0.8;"></i>
                            <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">Vault Synchronized</div>
                            <div class="text-meta">No cryptographic credentials require immediate attention.</div>
                        </div>
                    `;
                    return;
                }

                list.innerHTML = '';
                expiringProjects.forEach(p => {
                    const item = document.createElement('div');
                    item.className = 'notification-item warning';
                    item.onclick = () => {
                        window.location.href = `project.html?id=${p.id}`;
                    };
                    item.innerHTML = `
                        <i class="fa-solid fa-triangle-exclamation icon"></i>
                        <div class="content">
                            <div class="title">Credential Rotation Required</div>
                            <div class="desc"><b>${esc(p.name)}</b> has ${p.expiringKeyCount} API keys expiring within 7 days.</div>
                            <div class="time">Security Priority: High</div>
                        </div>
                    `;
                    list.appendChild(item);
                });

            } catch (err) {
                list.innerHTML = `
                    <div class="notification-empty">
                        <i class="fa-solid fa-circle-xmark" style="color: var(--error);"></i>
                        <div class="text-meta">Failed to retrieve security alerts</div>
                    </div>
                `;
            }
        };

        // Telemetry Orchestration
        checkNotifications();

        // Pulse check every 60 seconds, but only if user is active
        setInterval(checkNotifications, 60000);

        // Immediate check when returning to tab
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                checkNotifications();
            }
        });
    }

    // Helper: Escape HTML
    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
