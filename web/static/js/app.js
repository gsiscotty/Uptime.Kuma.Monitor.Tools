/**
 * Kuma Management Console - Modern Frontend
 * Enhanced UX with smooth interactions and animations
 */

// =============================================================================
// State
// =============================================================================
let monitors = [];
let notifications = [];
let tags = [];
let groups = [];
let selectedMonitors = new Set();
let isLoading = false;

// =============================================================================
// Initialization
// =============================================================================
document.addEventListener('DOMContentLoaded', function() {
    // Initialize editor if on editor page
    if (document.getElementById('monitors-list')) {
        loadData();
        // Start connection status monitoring
        startConnectionMonitor();
        // Check status immediately on load
        checkConnectionStatus();
        // Initialize filter auto-apply
        initFilterListeners();
    }
    
    // Auto-dismiss flash messages
    initFlashMessages();
    
    // Initialize tooltips and interactions
    initInteractions();
});

// =============================================================================
// Filter Listeners - Auto-apply on change
// =============================================================================
let filterDebounceTimer = null;

function initFilterListeners() {
    // Text inputs with debounce
    const textInputs = ['filter-name'];
    textInputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('input', () => {
                clearTimeout(filterDebounceTimer);
                filterDebounceTimer = setTimeout(applyFilters, 300);
            });
        }
    });
    
    // Select inputs - immediate apply
    const immediateInputs = ['filter-tags', 'filter-notification', 'filter-group', 'filter-type', 'filter-status'];
    immediateInputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', applyFilters);
        }
    });
}

// =============================================================================
// Connection Status Monitor
// =============================================================================
let connectionCheckInterval = null;

function startConnectionMonitor() {
    // Check connection status every 30 seconds
    connectionCheckInterval = setInterval(checkConnectionStatus, 30000);
    // Also check immediately after a short delay
    setTimeout(checkConnectionStatus, 5000);
}

async function checkConnectionStatus() {
    if (!document.getElementById('connection-status')) return;
    
    try {
        const response = await fetch('/kuma/api/validate-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });
        
        const result = await response.json();
        
        if (result.valid) {
            updateConnectionStatusUI(true);
        } else {
            updateConnectionStatusUI(false, result.error || result.message || 'Connection expired');
        }
    } catch (error) {
        console.error('Connection check failed:', error);
        updateConnectionStatusUI(false, 'Connection error');
    }
}

function stopConnectionMonitor() {
    if (connectionCheckInterval) {
        clearInterval(connectionCheckInterval);
        connectionCheckInterval = null;
    }
}

function initFlashMessages() {
    document.querySelectorAll('.alert').forEach(alert => {
        // Add entrance animation class
        alert.style.animationDelay = '0ms';
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            dismissAlert(alert);
        }, 5000);
    });
}

function dismissAlert(alert) {
    alert.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => alert.remove(), 300);
}

function initInteractions() {
    // Add ripple effect to buttons
    document.querySelectorAll('.btn').forEach(btn => {
        btn.addEventListener('click', createRipple);
    });
}

function createRipple(e) {
    const btn = e.currentTarget;
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement('span');
    
    ripple.className = 'ripple';
    ripple.style.left = `${e.clientX - rect.left}px`;
    ripple.style.top = `${e.clientY - rect.top}px`;
    
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
}

// Add ripple styles dynamically
const rippleStyles = document.createElement('style');
rippleStyles.textContent = `
    .btn { position: relative; overflow: hidden; }
    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.3);
        transform: scale(0);
        animation: ripple-animation 0.6s linear;
        pointer-events: none;
    }
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    @keyframes slideOut {
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(rippleStyles);

// =============================================================================
// Data Loading
// =============================================================================
async function loadData(forceRefresh = false) {
    if (isLoading) return;
    isLoading = true;
    
    const container = document.getElementById('monitors-list');
    container.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Loading monitors...</p>
        </div>
    `;
    
    // Build URL with refresh parameter for full data pull
    const refreshParam = forceRefresh ? '?refresh=true' : '';
    
    try {
        // Fetch all data in parallel with individual error handling
        // Pass refresh parameter to all endpoints for a full data pull
        const [monitorsRes, notificationsRes, tagsRes, groupsRes] = await Promise.all([
            fetch(`/kuma/api/monitors${refreshParam}`),
            fetch(`/kuma/api/notifications${refreshParam}`),
            fetch(`/kuma/api/tags${refreshParam}`),
            fetch(`/kuma/api/groups${refreshParam}`)
        ]);
        
        // Parse monitors (required)
        const monitorsData = await monitorsRes.json();
        if (!monitorsRes.ok || monitorsData.error) {
            throw new Error(monitorsData.error || 'Failed to load monitors');
        }
        monitors = monitorsData.monitors || [];
        
        // Parse notifications with fallback
        let loadWarnings = [];
        try {
            if (notificationsRes.ok) {
                const notificationsData = await notificationsRes.json();
                notifications = notificationsData.notifications || [];
            } else {
                console.warn('Notifications API returned:', notificationsRes.status);
                notifications = [];
                loadWarnings.push('notifications');
            }
        } catch (e) {
            console.error('Failed to parse notifications:', e);
            notifications = [];
            loadWarnings.push('notifications');
        }
        
        // Parse tags with fallback
        try {
            if (tagsRes.ok) {
                const tagsData = await tagsRes.json();
                tags = tagsData.tags || [];
            } else {
                console.warn('Tags API returned:', tagsRes.status);
                tags = [];
                loadWarnings.push('tags');
            }
        } catch (e) {
            console.error('Failed to parse tags:', e);
            tags = [];
            loadWarnings.push('tags');
        }
        
        // Parse groups with fallback
        try {
            if (groupsRes.ok) {
                const groupsData = await groupsRes.json();
                groups = groupsData.groups || [];
            } else {
                console.warn('Groups API returned:', groupsRes.status);
                groups = [];
                loadWarnings.push('groups');
            }
        } catch (e) {
            console.error('Failed to parse groups:', e);
            groups = [];
            loadWarnings.push('groups');
        }
        
        renderMonitors(monitors);
        populateSelects();
        updateStats();
        
        // Show warning if some data failed to load
        if (loadWarnings.length > 0) {
            showToast(`Some data failed to load: ${loadWarnings.join(', ')}. Try refreshing.`, 'error');
        }
        
        // If notifications is empty but we expected some, try loading again after a delay
        if (notifications.length === 0 && loadWarnings.includes('notifications')) {
            setTimeout(() => retryLoadNotifications(), 2000);
        }
        
    } catch (error) {
        console.error('Failed to load data:', error);
        container.innerHTML = `
            <div class="error-state">
                <span class="error-icon">⚠️</span>
                <p>Failed to load monitors</p>
                <p class="error-detail">${escapeHtml(error.message)}</p>
                <button class="btn btn-secondary" onclick="loadData()">Retry</button>
            </div>
        `;
    } finally {
        isLoading = false;
    }
}

async function retryLoadNotifications() {
    try {
        const response = await fetch('/kuma/api/notifications');
        if (response.ok) {
            const data = await response.json();
            if (data.notifications && data.notifications.length > 0) {
                notifications = data.notifications;
                populateSelects();
            }
        }
    } catch (e) {
        console.error('Retry load notifications failed:', e);
    }
}

async function reloadData() {
    const reloadBtn = document.querySelector('.btn-reload');
    if (reloadBtn) {
        reloadBtn.classList.add('spinning');
        reloadBtn.disabled = true;
    }
    
    try {
        // Validate connection first
        const connectionValid = await validateConnection();
        if (!connectionValid) {
            showToast('Connection expired - please re-authenticate', 'error');
            return;
        }
        
        // Clear selection before reload
        selectedMonitors.clear();
        
        // Force full refresh from server (clears all caches)
        await loadData(true);
        showToast('Data reloaded successfully', 'success');
        
    } catch (error) {
        console.error('Reload failed:', error);
        showToast('Failed to reload data', 'error');
    } finally {
        if (reloadBtn) {
            reloadBtn.classList.remove('spinning');
            reloadBtn.disabled = false;
        }
    }
}

async function refreshNotifications() {
    const statusEl = document.getElementById('notif-status');
    const notifSelect = document.getElementById('notif-select');
    
    if (statusEl) statusEl.textContent = 'Validating connection...';
    if (notifSelect) notifSelect.disabled = true;
    
    try {
        // First validate the connection/token
        const connectionValid = await validateConnection();
        if (!connectionValid) {
            if (statusEl) statusEl.textContent = 'Session expired';
            return; // Re-auth modal already shown by validateConnection
        }
        
        if (statusEl) statusEl.textContent = 'Loading...';
        
        const response = await fetch('/kuma/api/notifications');
        if (response.ok) {
            const data = await response.json();
            notifications = data.notifications || [];
            populateSelects();
            
            if (statusEl) {
                statusEl.textContent = notifications.length > 0 
                    ? `Loaded ${notifications.length} notification(s)` 
                    : 'No notifications found';
                setTimeout(() => { statusEl.textContent = ''; }, 3000);
            }
            
            if (notifications.length > 0) {
                showToast(`Loaded ${notifications.length} notifications`, 'success');
            }
        } else if (response.status === 401) {
            // Token might have expired during the request
            const data = await response.json();
            if (data.session_expired || data.expired) {
                pendingOperation = { type: 'refresh-notifications' };
                showReauthModal(data.message || 'Session expired. Please re-authenticate.');
                if (statusEl) statusEl.textContent = 'Session expired';
            } else {
                if (statusEl) statusEl.textContent = 'Auth failed';
                showToast('Authentication failed', 'error');
            }
        } else {
            if (statusEl) statusEl.textContent = 'Failed to load';
            showToast('Failed to load notifications', 'error');
        }
    } catch (e) {
        console.error('Refresh notifications failed:', e);
        if (statusEl) statusEl.textContent = 'Error loading';
        showToast('Error refreshing notifications', 'error');
    } finally {
        if (notifSelect) notifSelect.disabled = false;
    }
}

// Add loading styles
const loadingStyles = document.createElement('style');
loadingStyles.textContent = `
    .loading-state, .error-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 3rem;
        text-align: center;
        color: var(--text-muted);
    }
    .loading-spinner {
        width: 40px;
        height: 40px;
        border: 3px solid var(--border-color);
        border-top-color: var(--primary);
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
        margin-bottom: 1rem;
    }
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    .error-state .error-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
    }
    .error-state .error-detail {
        font-size: 0.875rem;
        margin-bottom: 1rem;
        color: var(--danger);
    }
`;
document.head.appendChild(loadingStyles);

// =============================================================================
// Rendering
// =============================================================================
function renderMonitors(monitorsToRender) {
    const container = document.getElementById('monitors-list');
    
    if (monitorsToRender.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">📭</span>
                <p>No monitors found</p>
                <p class="text-muted">Try adjusting your filters</p>
            </div>
        `;
        return;
    }
    
    // Sort by name
    const sorted = [...monitorsToRender].sort((a, b) => 
        a.name.toLowerCase().localeCompare(b.name.toLowerCase())
    );
    
    container.innerHTML = sorted.map((m, index) => `
        <div class="monitor-item ${selectedMonitors.has(m.id) ? 'selected' : ''}" 
             data-id="${m.id}"
             onclick="toggleMonitor(${m.id})"
             style="animation-delay: ${Math.min(index * 20, 500)}ms">
            <div class="monitor-checkbox">
                <input type="checkbox" 
                       ${selectedMonitors.has(m.id) ? 'checked' : ''}
                       onclick="event.stopPropagation(); toggleMonitor(${m.id})">
            </div>
            <div class="monitor-content">
                <div class="monitor-header">
                    <div class="monitor-name">
                        ${m.isGroup ? '<span class="type-badge group">📁 Group</span>' : `<span class="type-badge">${escapeHtml(m.type || 'http')}</span>`}
                        <span class="name-text">${escapeHtml(m.name)}</span>
                        ${!m.active ? '<span class="status-badge inactive">Paused</span>' : '<span class="status-badge active">Active</span>'}
                    </div>
                </div>
                <div class="monitor-details">
                    ${m.url ? `<div class="detail-item"><span class="detail-label">URL:</span> <span class="detail-value url">${escapeHtml(m.url.substring(0, 50))}${m.url.length > 50 ? '...' : ''}</span></div>` : ''}
                    ${m.group ? `<div class="detail-item"><span class="detail-label">Group:</span> <span class="detail-value">${escapeHtml(m.group)}</span></div>` : ''}
                    <div class="detail-item"><span class="detail-label">Interval:</span> <span class="detail-value">${m.interval || 60}s</span></div>
                    ${m.maxretries ? `<div class="detail-item"><span class="detail-label">Retries:</span> <span class="detail-value">${m.maxretries}</span></div>` : ''}
                </div>
                <div class="monitor-footer">
                    <div class="monitor-tags">
                        ${renderTags(m.tags)}
                    </div>
                    <div class="monitor-notifications">
                        ${renderNotifications(m.notifications)}
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    updateStats();
}

function renderTags(tagList) {
    if (!tagList || tagList.length === 0) return '<span class="no-data">No tags</span>';
    
    const maxVisible = 3;
    const visible = tagList.slice(0, maxVisible);
    const hidden = tagList.length - maxVisible;
    
    let html = visible.map(t => 
        `<span class="monitor-tag">${escapeHtml(t)}</span>`
    ).join('');
    
    if (hidden > 0) {
        html += `<span class="monitor-tag more">+${hidden}</span>`;
    }
    
    return html;
}

function renderNotifications(notifIds) {
    if (!notifIds || notifIds.length === 0) {
        return '<span class="no-data no-notifications">No notifications</span>';
    }
    
    const maxVisible = 2;
    const notifNames = notifIds.map(id => {
        const notif = notifications.find(n => n.id === id);
        return notif ? notif.name : `ID:${id}`;
    });
    
    const visible = notifNames.slice(0, maxVisible);
    const hidden = notifNames.length - maxVisible;
    
    let html = visible.map(name => 
        `<span class="notif-badge">${escapeHtml(name)}</span>`
    ).join('');
    
    if (hidden > 0) {
        const hiddenNames = notifNames.slice(maxVisible).join(', ');
        html += `<span class="notif-badge more" title="${escapeHtml(hiddenNames)}">+${hidden} more</span>`;
    }
    
    return html;
}

// Add more styles
const monitorStyles = document.createElement('style');
monitorStyles.textContent = `
    .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 3rem;
        text-align: center;
    }
    .empty-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
        opacity: 0.5;
    }
    .monitor-item {
        animation: fadeIn 0.3s ease forwards;
        opacity: 0;
        display: flex;
        gap: 1rem;
        padding: 1rem;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        margin-bottom: 0.75rem;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    .monitor-item:hover {
        border-color: var(--primary);
        background: var(--bg-hover);
    }
    .monitor-item.selected {
        border-color: var(--primary);
        background: rgba(16, 185, 129, 0.1);
        box-shadow: 0 0 0 1px var(--primary);
    }
    .monitor-checkbox {
        display: flex;
        align-items: flex-start;
        padding-top: 0.25rem;
    }
    .monitor-checkbox input[type="checkbox"] {
        width: 18px;
        height: 18px;
        cursor: pointer;
    }
    .monitor-content {
        flex: 1;
        min-width: 0;
    }
    .monitor-header {
        margin-bottom: 0.5rem;
    }
    .monitor-name {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
    }
    .name-text {
        font-weight: 600;
        font-size: 1rem;
        color: var(--text-primary);
    }
    .type-badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        font-size: 0.7rem;
        border-radius: 4px;
        background: var(--bg-hover);
        color: var(--text-muted);
        font-weight: 500;
        text-transform: uppercase;
    }
    .type-badge.group {
        background: rgba(139, 92, 246, 0.2);
        color: #a78bfa;
    }
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        font-size: 0.65rem;
        border-radius: 9999px;
        font-weight: 600;
        text-transform: uppercase;
    }
    .status-badge.active {
        background: rgba(16, 185, 129, 0.2);
        color: var(--primary);
    }
    .status-badge.inactive {
        background: rgba(245, 158, 11, 0.2);
        color: var(--warning);
    }
    .monitor-details {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem 1.5rem;
        margin-bottom: 0.75rem;
        font-size: 0.8125rem;
    }
    .detail-item {
        display: flex;
        align-items: center;
        gap: 0.25rem;
    }
    .detail-label {
        color: var(--text-muted);
    }
    .detail-value {
        color: var(--text-secondary);
    }
    .detail-value.url {
        font-family: monospace;
        font-size: 0.75rem;
        color: var(--primary-light);
    }
    .monitor-footer {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .monitor-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 0.375rem;
        flex: 1;
    }
    .monitor-notifications {
        display: flex;
        flex-wrap: wrap;
        gap: 0.375rem;
        justify-content: flex-end;
    }
    .notif-badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        font-size: 0.7rem;
        border-radius: 4px;
        background: rgba(59, 130, 246, 0.2);
        color: #60a5fa;
        font-weight: 500;
    }
    .notif-badge.more {
        background: rgba(59, 130, 246, 0.3);
        cursor: help;
    }
    .no-data {
        font-size: 0.75rem;
        color: var(--text-muted);
        font-style: italic;
    }
    .no-data.no-notifications {
        color: rgba(239, 68, 68, 0.7);
    }
    .monitor-tag {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        font-size: 0.7rem;
        border-radius: 4px;
        background: var(--bg-hover);
        color: var(--text-secondary);
    }
    .monitor-tag.more {
        background: var(--primary);
        color: white;
        font-weight: 600;
    }
    @keyframes fadeIn {
        to { opacity: 1; }
    }
`;
document.head.appendChild(monitorStyles);

function populateSelects() {
    // Notifications (for bulk edit) - always show all
    const notifSelect = document.getElementById('notif-select');
    if (notifSelect) {
        if (notifications.length === 0) {
            notifSelect.innerHTML = '<option value="" disabled>No notifications available - click refresh</option>';
        } else {
            notifSelect.innerHTML = notifications
                .sort((a, b) => a.name.localeCompare(b.name))
                .map(n => `<option value="${n.id}">${escapeHtml(n.name)}</option>`)
                .join('');
        }
    }
    
    // Notification filter dropdown - show all initially
    const notifFilter = document.getElementById('filter-notification');
    if (notifFilter) {
        const notifOptions = notifications
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(n => `<option value="${n.id}">${escapeHtml(n.name)}</option>`)
            .join('');
        notifFilter.innerHTML = '<option value="">All Notifications</option><option value="_none">No Notifications</option>' + notifOptions;
    }
    
    // Tags (for bulk edit)
    const tagsSelect = document.getElementById('tags-select');
    if (tagsSelect) {
        tagsSelect.innerHTML = tags
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`)
            .join('');
    }
    
    // Tags filter dropdown
    const tagsFilter = document.getElementById('filter-tags');
    if (tagsFilter) {
        const tagOptions = tags
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(t => `<option value="${t.name}">${escapeHtml(t.name)}</option>`)
            .join('');
        tagsFilter.innerHTML = '<option value="">All Tags</option><option value="_none">No Tags</option>' + tagOptions;
    }
    
    // Groups - show all initially
    const groupOptions = groups
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`)
        .join('');
    
    const groupFilter = document.getElementById('filter-group');
    const groupSelect = document.getElementById('group-select');
    
    if (groupFilter) {
        groupFilter.innerHTML = '<option value="">All Groups</option>' + groupOptions;
    }
    if (groupSelect) {
        groupSelect.innerHTML = groupOptions || '<option value="">No groups available</option>';
    }
}

// Update filter dropdowns based on currently filtered monitors
function updateFilterOptions(filteredMonitors) {
    // Collect unique values from filtered monitors
    const availableNotifIds = new Set();
    const availableGroupIds = new Set();
    const availableTags = new Set();
    let hasNoNotifications = false;
    let hasNoTags = false;
    
    filteredMonitors.forEach(m => {
        // Notifications
        if (m.notifications && m.notifications.length > 0) {
            m.notifications.forEach(nid => availableNotifIds.add(nid));
        } else {
            hasNoNotifications = true;
        }
        // Groups
        if (m.groupId) {
            availableGroupIds.add(m.groupId);
        }
        // Tags
        if (m.tags && m.tags.length > 0) {
            m.tags.forEach(t => availableTags.add(t.toLowerCase()));
        } else {
            hasNoTags = true;
        }
    });
    
    // Update notification filter dropdown
    const notifFilter = document.getElementById('filter-notification');
    if (notifFilter) {
        const currentValue = notifFilter.value;
        
        // Build options based on what's available
        let options = '<option value="">All Notifications</option>';
        if (hasNoNotifications) {
            options += '<option value="_none">No Notifications</option>';
        }
        
        // Add available notifications with count
        notifications
            .filter(n => availableNotifIds.has(n.id))
            .sort((a, b) => a.name.localeCompare(b.name))
            .forEach(n => {
                const count = filteredMonitors.filter(m => m.notifications && m.notifications.includes(n.id)).length;
                options += `<option value="${n.id}">${escapeHtml(n.name)} (${count})</option>`;
            });
        
        notifFilter.innerHTML = options;
        
        // Restore selection if still valid
        if (currentValue && notifFilter.querySelector(`option[value="${currentValue}"]`)) {
            notifFilter.value = currentValue;
        }
    }
    
    // Update group filter dropdown
    const groupFilter = document.getElementById('filter-group');
    if (groupFilter) {
        const currentValue = groupFilter.value;
        
        let options = '<option value="">All Groups</option>';
        
        // Add available groups with count
        groups
            .filter(g => availableGroupIds.has(g.id))
            .sort((a, b) => a.name.localeCompare(b.name))
            .forEach(g => {
                const count = filteredMonitors.filter(m => m.groupId == g.id).length;
                options += `<option value="${g.id}">${escapeHtml(g.name)} (${count})</option>`;
            });
        
        // Also add groups for monitors without a group
        const noGroupCount = filteredMonitors.filter(m => !m.groupId).length;
        if (noGroupCount > 0) {
            options += `<option value="_none">No Group (${noGroupCount})</option>`;
        }
        
        groupFilter.innerHTML = options;
        
        // Restore selection if still valid
        if (currentValue && groupFilter.querySelector(`option[value="${currentValue}"]`)) {
            groupFilter.value = currentValue;
        }
    }
    
    // Update tags filter dropdown
    const tagsFilter = document.getElementById('filter-tags');
    if (tagsFilter) {
        const currentValue = tagsFilter.value;
        
        let options = '<option value="">All Tags</option>';
        if (hasNoTags) {
            const noTagCount = filteredMonitors.filter(m => !m.tags || m.tags.length === 0).length;
            options += `<option value="_none">No Tags (${noTagCount})</option>`;
        }
        
        // Add available tags with count
        tags
            .filter(t => availableTags.has(t.name.toLowerCase()))
            .sort((a, b) => a.name.localeCompare(b.name))
            .forEach(t => {
                const count = filteredMonitors.filter(m => m.tags && m.tags.some(mt => mt.toLowerCase() === t.name.toLowerCase())).length;
                options += `<option value="${t.name}">${escapeHtml(t.name)} (${count})</option>`;
            });
        
        tagsFilter.innerHTML = options;
        
        // Restore selection if still valid
        if (currentValue && tagsFilter.querySelector(`option[value="${currentValue}"]`)) {
            tagsFilter.value = currentValue;
        }
    }
}

function updateStats() {
    const countBadge = document.getElementById('monitor-count');
    const selectedCount = document.getElementById('selected-count');
    
    // Count currently displayed monitors (after filtering)
    const displayedMonitors = document.querySelectorAll('.monitor-item').length;
    
    if (countBadge) {
        // Show filtered count vs total if filtered
        if (displayedMonitors !== monitors.length && monitors.length > 0) {
            countBadge.textContent = `${displayedMonitors}/${monitors.length}`;
            countBadge.title = `Showing ${displayedMonitors} of ${monitors.length} monitors`;
        } else {
            countBadge.textContent = monitors.length;
            countBadge.title = `${monitors.length} monitors`;
        }
    }
    if (selectedCount) {
        selectedCount.textContent = selectedMonitors.size;
        
        // Add visual feedback
        if (selectedMonitors.size > 0) {
            selectedCount.parentElement.classList.add('has-selection');
        } else {
            selectedCount.parentElement.classList.remove('has-selection');
        }
    }
    
    // Enable/disable apply button
    const applyBtn = document.getElementById('apply-btn');
    if (applyBtn) {
        const hasChanges = hasSelectedChanges();
        applyBtn.disabled = selectedMonitors.size === 0 || !hasChanges;
        
        if (selectedMonitors.size > 0 && hasChanges) {
            applyBtn.classList.add('ready');
        } else {
            applyBtn.classList.remove('ready');
        }
    }
}

function hasSelectedChanges() {
    const changeCheckboxes = document.querySelectorAll('[id^="change-"]:checked');
    return changeCheckboxes.length > 0;
}

// Add selection styles
const selectionStyles = document.createElement('style');
selectionStyles.textContent = `
    .selected-info.has-selection {
        color: var(--primary-light);
        font-weight: 500;
    }
    .btn.ready {
        animation: pulse-glow 2s ease-in-out infinite;
    }
    @keyframes pulse-glow {
        0%, 100% { box-shadow: var(--shadow-md), 0 0 20px rgba(16, 185, 129, 0.2); }
        50% { box-shadow: var(--shadow-lg), 0 0 30px rgba(16, 185, 129, 0.4); }
    }
`;
document.head.appendChild(selectionStyles);

// =============================================================================
// Monitor Selection
// =============================================================================
function toggleMonitor(id) {
    if (selectedMonitors.has(id)) {
        selectedMonitors.delete(id);
    } else {
        selectedMonitors.add(id);
    }
    
    const item = document.querySelector(`.monitor-item[data-id="${id}"]`);
    if (item) {
        item.classList.toggle('selected', selectedMonitors.has(id));
        const checkbox = item.querySelector('input[type="checkbox"]');
        if (checkbox) checkbox.checked = selectedMonitors.has(id);
        
        // Add selection animation
        if (selectedMonitors.has(id)) {
            item.style.transform = 'scale(1.01)';
            setTimeout(() => item.style.transform = '', 150);
        }
    }
    
    updateStats();
}

function selectAll() {
    const items = document.querySelectorAll('.monitor-item');
    items.forEach(item => {
        const id = parseInt(item.dataset.id);
        selectedMonitors.add(id);
        item.classList.add('selected');
        item.querySelector('input[type="checkbox"]').checked = true;
    });
    updateStats();
    showToast(`Selected ${items.length} monitors`);
}

function selectNone() {
    selectedMonitors.clear();
    document.querySelectorAll('.monitor-item').forEach(item => {
        item.classList.remove('selected');
        item.querySelector('input[type="checkbox"]').checked = false;
    });
    updateStats();
    showToast('Selection cleared');
}

function invertSelection() {
    document.querySelectorAll('.monitor-item').forEach(item => {
        const id = parseInt(item.dataset.id);
        if (selectedMonitors.has(id)) {
            selectedMonitors.delete(id);
            item.classList.remove('selected');
            item.querySelector('input[type="checkbox"]').checked = false;
        } else {
            selectedMonitors.add(id);
            item.classList.add('selected');
            item.querySelector('input[type="checkbox"]').checked = true;
        }
    });
    updateStats();
    showToast(`${selectedMonitors.size} monitors selected`);
}

// =============================================================================
// Toast Notifications
// =============================================================================
function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 2500);
}

// Add toast styles
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    .toast {
        position: fixed;
        bottom: 2rem;
        left: 50%;
        transform: translateX(-50%) translateY(100px);
        padding: 0.75rem 1.5rem;
        background: var(--bg-card-solid);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-full);
        color: var(--text-primary);
        font-size: 0.875rem;
        box-shadow: var(--shadow-xl);
        z-index: 3000;
        opacity: 0;
        transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }
    .toast.show {
        transform: translateX(-50%) translateY(0);
        opacity: 1;
    }
    .toast-success { border-color: var(--success); }
    .toast-error { border-color: var(--danger); }
`;
document.head.appendChild(toastStyles);

// =============================================================================
// Filtering
// =============================================================================

// Track negate state for each filter
const filterNegateState = {
    name: false,
    tags: false,
    notification: false,
    group: false,
    type: false,
    status: false
};

function toggleNegate(filterName) {
    filterNegateState[filterName] = !filterNegateState[filterName];
    const btn = document.getElementById(`negate-${filterName}`);
    if (btn) {
        btn.classList.toggle('active', filterNegateState[filterName]);
        btn.title = filterNegateState[filterName] ? 'Excluding matches (click to include)' : 'Exclude matches';
    }
    // Update filter card visual states
    updateFilterCardStates();
    // Re-apply filters when negate state changes
    applyFilters();
}

function isNegated(filterName) {
    return filterNegateState[filterName] === true;
}

function resetNegateStates() {
    for (const key in filterNegateState) {
        filterNegateState[key] = false;
        const btn = document.getElementById(`negate-${key}`);
        if (btn) {
            btn.classList.remove('active');
            btn.title = 'Exclude matches';
        }
    }
}

function updateFilterCardStates() {
    // Update visual state of filter cards based on whether they have values
    const filters = [
        { id: 'filter-name', cardIndex: 0 },
        { id: 'filter-tags', cardIndex: 1 },
        { id: 'filter-notification', cardIndex: 2 },
        { id: 'filter-group', cardIndex: 3 },
        { id: 'filter-type', cardIndex: 4 },
        { id: 'filter-status', cardIndex: 5 }
    ];
    
    const filterCards = document.querySelectorAll('.filter-card');
    
    filters.forEach(filter => {
        const el = document.getElementById(filter.id);
        const card = filterCards[filter.cardIndex];
        if (!el || !card) return;
        
        const hasValue = el.value && el.value.trim() !== '';
        const isNegated = filterNegateState[filter.id.replace('filter-', '')];
        
        if (hasValue || isNegated) {
            card.classList.add('filter-active');
        } else {
            card.classList.remove('filter-active');
        }
    });
}

function applyFilters(showFeedback = false) {
    const nameFilterRaw = document.getElementById('filter-name').value.trim();
    const tagFilter = document.getElementById('filter-tags')?.value || '';
    const notifFilter = document.getElementById('filter-notification')?.value || '';
    const groupFilter = document.getElementById('filter-group').value;
    const typeFilter = document.getElementById('filter-type').value;
    const statusFilter = document.getElementById('filter-status')?.value || '';
    
    // Update visual state of filter cards
    updateFilterCardStates();
    
    // Parse name filter - support multiple comma-separated terms
    const nameTerms = nameFilterRaw
        .split(',')
        .map(t => t.trim().toLowerCase())
        .filter(t => t.length > 0);
    
    const filtered = monitors.filter(m => {
        // Name filter with negate support (OR logic for multiple terms)
        if (nameTerms.length > 0) {
            const monitorName = m.name.toLowerCase();
            const matches = nameTerms.some(term => monitorName.includes(term));
            if (isNegated('name')) {
                if (matches) return false; // Exclude if ANY term matches
            } else {
                if (!matches) return false; // Include only if ANY term matches
            }
        }
        
        // Tag filter (dropdown) with negate support
        if (tagFilter) {
            const monitorTags = m.tags || [];
            let matches;
            if (tagFilter === '_none') {
                matches = monitorTags.length === 0;
            } else {
                matches = monitorTags.some(t => t.toLowerCase() === tagFilter.toLowerCase());
            }
            if (isNegated('tags')) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
        }
        
        // Notification filter with negate support
        if (notifFilter) {
            const monitorNotifs = m.notifications || [];
            let matches;
            if (notifFilter === '_none') {
                matches = monitorNotifs.length === 0;
            } else {
                const notifId = parseInt(notifFilter);
                matches = monitorNotifs.includes(notifId);
            }
            if (isNegated('notification')) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
        }
        
        // Group filter with negate support
        if (groupFilter) {
            let matches;
            if (groupFilter === '_none') {
                matches = !m.groupId;
            } else {
                matches = m.groupId == groupFilter;
            }
            if (isNegated('group')) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
        }
        
        // Type filter with negate support
        if (typeFilter) {
            let matches;
            if (typeFilter === 'group') {
                matches = m.isGroup;
            } else if (typeFilter === 'monitor') {
                matches = !m.isGroup;
            } else {
                matches = true;
            }
            if (isNegated('type')) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
        }
        
        // Status filter with negate support
        if (statusFilter) {
            let matches;
            if (statusFilter === 'active') {
                matches = m.active;
            } else if (statusFilter === 'paused') {
                matches = !m.active;
            } else {
                matches = true;
            }
            if (isNegated('status')) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
        }
        
        return true;
    });
    
    renderMonitors(filtered);
    
    // Update filter dropdowns to show available options in filtered results
    updateFilterOptions(filtered);
    
    // Only show toast when manually clicking Apply button
    if (showFeedback) {
        showToast(`Found ${filtered.length} monitor(s)`);
    }
}

function clearFilters() {
    document.getElementById('filter-name').value = '';
    const tagsFilter = document.getElementById('filter-tags');
    if (tagsFilter) tagsFilter.value = '';
    const notifFilter = document.getElementById('filter-notification');
    if (notifFilter) notifFilter.value = '';
    document.getElementById('filter-group').value = '';
    document.getElementById('filter-type').value = '';
    const statusFilter = document.getElementById('filter-status');
    if (statusFilter) statusFilter.value = '';
    
    // Reset all negate toggles
    resetNegateStates();
    
    // Update filter card visual states
    updateFilterCardStates();
    
    // Re-populate selects with all options (no counts)
    populateSelects();
    
    renderMonitors(monitors);
    showToast('Filters cleared');
}

// =============================================================================
// Change Toggles
// =============================================================================
function toggleChangeCard(type) {
    const card = document.getElementById(`card-${type}`);
    const checkbox = document.getElementById(`change-${type}`);
    
    if (!card || !checkbox) return;
    
    // Toggle the checkbox
    checkbox.checked = !checkbox.checked;
    
    // Toggle the card active state
    card.classList.toggle('active', checkbox.checked);
    
    // Special handling for group action
    if (type === 'group') {
        const action = document.getElementById('group-action');
        const wrapper = document.getElementById('group-select-wrapper');
        if (action && wrapper) {
            // Initial state
            wrapper.classList.toggle('hidden', action.value === 'clear');
            // On change
            action.onchange = function() {
                wrapper.classList.toggle('hidden', this.value === 'clear');
            };
        }
    }
    
    updateStats();
}

// Legacy toggle function (for backward compatibility)
function toggleChange(type) {
    const checkbox = document.getElementById(`change-${type}`);
    const options = document.getElementById(`change-${type}-options`);
    
    if (options) {
        if (checkbox.checked) {
            options.classList.remove('hidden');
            options.style.animation = 'slideDown 0.2s ease';
        } else {
            options.classList.add('hidden');
        }
    }
    
    // Special handling for group action
    if (type === 'group') {
        const action = document.getElementById('group-action');
        const wrapper = document.getElementById('group-select-wrapper');
        if (action && wrapper) {
            action.onchange = function() {
                wrapper.classList.toggle('hidden', this.value === 'clear');
            };
        }
    }
    
    updateStats();
}

function togglePanel(panelId) {
    const panel = document.getElementById(panelId);
    if (panel) {
        panel.classList.toggle('hidden');
    }
}

// =============================================================================
// Bulk Operations
// =============================================================================

function clearBulkChanges() {
    // Uncheck all change cards
    const checkboxes = document.querySelectorAll('.change-card-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = false;
    });
    
    // Remove active state from all cards
    const cards = document.querySelectorAll('.change-card');
    cards.forEach(card => {
        card.classList.remove('active');
    });
    
    // Reset form values
    const notifAction = document.getElementById('notif-action');
    if (notifAction) notifAction.value = 'add';
    
    const notifSelect = document.getElementById('notif-select');
    if (notifSelect) notifSelect.value = '';
    
    const tagsAction = document.getElementById('tags-action');
    if (tagsAction) tagsAction.value = 'add';
    
    const tagsSelect = document.getElementById('tags-select');
    if (tagsSelect) tagsSelect.value = '';
    
    const groupSelect = document.getElementById('group-select');
    if (groupSelect) groupSelect.value = '';
    
    const intervalValue = document.getElementById('interval-value');
    if (intervalValue) intervalValue.value = '';
    
    const retriesValue = document.getElementById('retries-value');
    if (retriesValue) retriesValue.value = '';
    
    const activeAction = document.getElementById('active-action');
    if (activeAction) activeAction.value = 'enable';
}

function buildChanges() {
    const changes = {};
    
    if (document.getElementById('change-notifications')?.checked) {
        const action = document.getElementById('notif-action')?.value;
        const selectEl = document.getElementById('notif-select');
        const selected = selectEl ? Array.from(selectEl.selectedOptions).map(o => parseInt(o.value)) : [];
        if (selected.length > 0 && action) {
            changes.notificationAction = action;
            changes.notificationIds = selected;
        }
    }
    
    if (document.getElementById('change-interval')?.checked) {
        const value = parseInt(document.getElementById('interval-value').value);
        if (value >= 20) changes.interval = value;
    }
    
    if (document.getElementById('change-retries')?.checked) {
        const value = parseInt(document.getElementById('retries-value').value);
        if (value >= 0) changes.maxretries = value;
    }
    
    if (document.getElementById('change-retry-interval')?.checked) {
        const value = parseInt(document.getElementById('retry-interval-value').value);
        if (value >= 20) changes.retryInterval = value;
    }
    
    if (document.getElementById('change-resend')?.checked) {
        const value = parseInt(document.getElementById('resend-value').value);
        if (value >= 0) changes.resendInterval = value;
    }
    
    if (document.getElementById('change-upside-down')?.checked) {
        changes.upsideDown = document.getElementById('upside-down-value').checked;
    }
    
    if (document.getElementById('change-group')?.checked) {
        const action = document.getElementById('group-action').value;
        if (action === 'clear') {
            changes.parent = null;
        } else {
            const groupId = parseInt(document.getElementById('group-select').value);
            if (groupId) changes.parent = groupId;
        }
    }
    
    if (document.getElementById('change-tags')?.checked) {
        const action = document.getElementById('tags-action')?.value;
        const selectEl = document.getElementById('tags-select');
        const selected = selectEl ? Array.from(selectEl.selectedOptions).map(o => parseInt(o.value)) : [];
        if (selected.length > 0 && action) {
            changes.tagAction = action;
            changes.tagIds = selected;
        }
    }
    
    return changes;
}

async function previewChanges() {
    if (selectedMonitors.size === 0) {
        showToast('Please select at least one monitor', 'error');
        return;
    }
    
    const changes = buildChanges();
    if (Object.keys(changes).length === 0) {
        showToast('Please select at least one change', 'error');
        return;
    }
    
    // Validate connection before showing preview
    const connectionValid = await validateConnection();
    if (!connectionValid) {
        return; // Re-auth modal already shown
    }
    
    const selectedList = monitors.filter(m => selectedMonitors.has(m.id));
    
    // Build change descriptions
    const changeDescriptions = [];
    if (changes.interval) changeDescriptions.push(`<strong>Interval:</strong> ${changes.interval}s`);
    if (changes.maxretries !== undefined) changeDescriptions.push(`<strong>Retries:</strong> ${changes.maxretries}`);
    if (changes.retryInterval) changeDescriptions.push(`<strong>Retry Interval:</strong> ${changes.retryInterval}s`);
    if (changes.resendInterval !== undefined) changeDescriptions.push(`<strong>Resend:</strong> ${changes.resendInterval}`);
    if (changes.upsideDown !== undefined) changeDescriptions.push(`<strong>Upside Down:</strong> ${changes.upsideDown ? 'Yes' : 'No'}`);
    if (changes.parent !== undefined) {
        const groupName = changes.parent === null ? 'None' : groups.find(g => g.id === changes.parent)?.name || changes.parent;
        changeDescriptions.push(`<strong>Group:</strong> ${groupName}`);
    }
    if (changes.notificationIds) {
        const names = changes.notificationIds.map(id => notifications.find(n => n.id === id)?.name || id);
        changeDescriptions.push(`<strong>Notifications:</strong> ${changes.notificationAction} [${names.join(', ')}]`);
    }
    if (changes.tagIds) {
        const names = changes.tagIds.map(id => tags.find(t => t.id === id)?.name || id);
        changeDescriptions.push(`<strong>Tags:</strong> ${changes.tagAction} [${names.join(', ')}]`);
    }
    
    let previewHtml = `
        <div class="preview-summary">
            <p>Apply changes to <strong>${selectedList.length}</strong> monitor(s)</p>
        </div>
        
        <div class="preview-item">
            <strong>Changes to apply:</strong>
            <ul class="change-list">
                ${changeDescriptions.map(d => `<li>${d}</li>`).join('')}
            </ul>
        </div>
    `;
    
    previewHtml += `
        <div class="preview-item">
            <strong>Affected monitors:</strong>
            <div class="monitor-preview-list" id="preview-monitors-list">
    `;
    
    const initialCount = 5;
    selectedList.slice(0, initialCount).forEach(m => {
        previewHtml += `
            <div class="monitor-preview-item">
                ${m.isGroup ? '📁' : '📡'} ${escapeHtml(m.name)}
            </div>
        `;
    });
    
    if (selectedList.length > initialCount) {
        // Hidden items
        previewHtml += `<div class="monitor-preview-hidden" id="preview-monitors-hidden" style="display: none;">`;
        selectedList.slice(initialCount).forEach(m => {
            previewHtml += `
                <div class="monitor-preview-item">
                    ${m.isGroup ? '📁' : '📡'} ${escapeHtml(m.name)}
                </div>
            `;
        });
        previewHtml += `</div>`;
        
        // Show all / Show less toggle
        previewHtml += `
            <div class="monitor-preview-toggle">
                <button type="button" class="btn-link" id="preview-toggle-btn" onclick="togglePreviewMonitors()">
                    Show all ${selectedList.length} monitors
                </button>
            </div>
        `;
    }
    
    previewHtml += `</div></div>`;
    
    // Show modal
    document.getElementById('preview-content').innerHTML = previewHtml;
    document.getElementById('preview-modal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

// Toggle show all/less monitors in preview
function togglePreviewMonitors() {
    const hiddenEl = document.getElementById('preview-monitors-hidden');
    const toggleBtn = document.getElementById('preview-toggle-btn');
    const listEl = document.getElementById('preview-monitors-list');
    
    if (!hiddenEl || !toggleBtn) return;
    
    const isHidden = hiddenEl.style.display === 'none';
    
    if (isHidden) {
        hiddenEl.style.display = 'block';
        toggleBtn.textContent = 'Show less';
        // Expand max-height for scrolling
        if (listEl) listEl.style.maxHeight = '400px';
    } else {
        hiddenEl.style.display = 'none';
        const totalCount = document.querySelectorAll('.monitor-preview-item').length;
        toggleBtn.textContent = `Show all ${totalCount} monitors`;
        if (listEl) listEl.style.maxHeight = '200px';
    }
}

// Add preview styles
const previewStyles = document.createElement('style');
previewStyles.textContent = `
    .preview-summary {
        text-align: center;
        padding-bottom: 1rem;
        margin-bottom: 1rem;
        border-bottom: 1px solid var(--border-color);
    }
    .preview-summary p {
        font-size: 1.125rem;
    }
    .preview-summary.preview-danger {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: var(--radius-md);
        padding: 1.5rem;
        margin: -1rem -1rem 1rem -1rem;
    }
    .preview-summary.preview-danger p {
        color: var(--danger);
    }
    .preview-summary .danger-warning {
        font-size: 0.875rem;
        margin-top: 0.5rem;
        color: var(--text-muted);
    }
    .change-list-danger li {
        color: var(--danger);
        background: rgba(239, 68, 68, 0.1);
        border-radius: var(--radius-sm);
        padding: 0.75rem !important;
    }
    .change-list {
        list-style: none;
        padding: 0;
        margin: 0.75rem 0 0 0;
    }
    .change-list li {
        padding: 0.5rem 0;
        border-bottom: 1px solid var(--border-light);
    }
    .change-list li:last-child {
        border-bottom: none;
    }
    .monitor-preview-list {
        margin-top: 0.75rem;
        max-height: 200px;
        overflow-y: auto;
    }
    .monitor-preview-item {
        padding: 0.5rem;
        font-size: 0.875rem;
        border-radius: var(--radius-sm);
    }
    .monitor-preview-item:hover {
        background: var(--bg-hover);
    }
    .monitor-preview-toggle {
        padding: 0.75rem 0.5rem;
        text-align: center;
        border-top: 1px solid var(--border-light);
        margin-top: 0.5rem;
    }
    .btn-link {
        background: none;
        border: none;
        color: var(--primary-light);
        cursor: pointer;
        font-size: 0.875rem;
        text-decoration: underline;
        padding: 0;
    }
    .btn-link:hover {
        color: var(--primary);
    }
`;
document.head.appendChild(previewStyles);

function closeModal() {
    const modal = document.getElementById('preview-modal');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
}

async function confirmApply() {
    closeModal();
    await applyChanges();
}

// =============================================================================
// Manage Tags Modal
// =============================================================================
function openManageTagsModal() {
    const modal = document.getElementById('manage-tags-modal');
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        loadTagsList();
    }
}

function closeManageTagsModal() {
    const modal = document.getElementById('manage-tags-modal');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
}

async function loadTagsList() {
    const container = document.getElementById('tags-list');
    if (!container) return;
    
    container.innerHTML = '<div class="loading-state"><span class="loading-spinner"></span> Loading tags...</div>';
    
    try {
        const response = await fetch('/kuma/api/tags');
        const data = await response.json();
        
        if (data.tags && data.tags.length > 0) {
            container.innerHTML = data.tags
                .sort((a, b) => a.name.localeCompare(b.name))
                .map(t => `
                    <div class="manage-item" data-id="${t.id}">
                        <div class="manage-item-info">
                            <span class="tag-color-dot" style="background: ${t.color || '#4B5563'}"></span>
                            <span class="manage-item-name">${escapeHtml(t.name)}</span>
                            <span class="manage-item-id">ID: ${t.id}</span>
                        </div>
                        <button class="btn btn-danger btn-sm" onclick="deleteTag(${t.id}, '${escapeHtml(t.name)}')">
                            🗑️ Delete
                        </button>
                    </div>
                `).join('');
        } else {
            container.innerHTML = '<div class="empty-state">No tags found. Create one above!</div>';
        }
    } catch (error) {
        console.error('Failed to load tags:', error);
        container.innerHTML = '<div class="error-state">Failed to load tags</div>';
    }
}

async function createTag() {
    const nameInput = document.getElementById('new-tag-name');
    const colorInput = document.getElementById('new-tag-color');
    
    const name = nameInput?.value?.trim();
    const color = colorInput?.value || '#4B5563';
    
    if (!name) {
        showToast('Please enter a tag name', 'error');
        return;
    }
    
    try {
        const response = await fetch('/kuma/api/tags', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ name, color })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`Tag "${name}" created!`, 'success');
            nameInput.value = '';
            loadTagsList();
            // Force full refresh of main data
            await loadData(true);
            showChangesBanner();
        } else {
            showToast(result.error || 'Failed to create tag', 'error');
        }
    } catch (error) {
        console.error('Create tag failed:', error);
        showToast('Failed to create tag', 'error');
    }
}

async function deleteTag(tagId, tagName) {
    if (!confirm(`Delete tag "${tagName}"?\n\nThis will remove the tag from all monitors.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/kuma/api/tags/${tagId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': csrfToken
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`Tag "${tagName}" deleted!`, 'success');
            loadTagsList();
            // Force full refresh of main data
            await loadData(true);
            showChangesBanner();
        } else {
            showToast(result.error || 'Failed to delete tag', 'error');
        }
    } catch (error) {
        console.error('Delete tag failed:', error);
        showToast('Failed to delete tag', 'error');
    }
}

// =============================================================================
// Manage Groups Modal
// =============================================================================
function openManageGroupsModal() {
    const modal = document.getElementById('manage-groups-modal');
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        loadGroupsList();
    }
}

function closeManageGroupsModal() {
    const modal = document.getElementById('manage-groups-modal');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
}

async function loadGroupsList() {
    const container = document.getElementById('groups-list');
    if (!container) return;
    
    container.innerHTML = '<div class="loading-state"><span class="loading-spinner"></span> Loading groups...</div>';
    
    try {
        const response = await fetch('/kuma/api/groups');
        const data = await response.json();
        
        if (data.groups && data.groups.length > 0) {
            // Count monitors per group
            const groupCounts = {};
            monitors.forEach(m => {
                if (m.groupId) {
                    groupCounts[m.groupId] = (groupCounts[m.groupId] || 0) + 1;
                }
            });
            
            container.innerHTML = data.groups
                .sort((a, b) => a.name.localeCompare(b.name))
                .map(g => {
                    const count = groupCounts[g.id] || 0;
                    return `
                        <div class="manage-item" data-id="${g.id}">
                            <div class="manage-item-info">
                                <span class="manage-item-icon">📁</span>
                                <span class="manage-item-name">${escapeHtml(g.name)}</span>
                                <span class="manage-item-count">${count} monitor${count !== 1 ? 's' : ''}</span>
                            </div>
                            <button class="btn btn-danger btn-sm" onclick="deleteGroup(${g.id}, '${escapeHtml(g.name)}', ${count})" ${count > 0 ? 'disabled title="Remove monitors first"' : ''}>
                                🗑️ Delete
                            </button>
                        </div>
                    `;
                }).join('');
        } else {
            container.innerHTML = '<div class="empty-state">No groups found. Create one above!</div>';
        }
    } catch (error) {
        console.error('Failed to load groups:', error);
        container.innerHTML = '<div class="error-state">Failed to load groups</div>';
    }
}

async function createGroup() {
    const nameInput = document.getElementById('new-group-name');
    const name = nameInput?.value?.trim();
    
    if (!name) {
        showToast('Please enter a group name', 'error');
        return;
    }
    
    try {
        const response = await fetch('/kuma/api/groups', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ name })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`Group "${name}" created!`, 'success');
            nameInput.value = '';
            loadGroupsList();
            // Force full refresh of main data
            await loadData(true);
            showChangesBanner();
        } else {
            showToast(result.error || 'Failed to create group', 'error');
        }
    } catch (error) {
        console.error('Create group failed:', error);
        showToast('Failed to create group', 'error');
    }
}

async function deleteGroup(groupId, groupName, monitorCount) {
    if (monitorCount > 0) {
        showToast(`Cannot delete "${groupName}" - it contains ${monitorCount} monitor(s). Remove them first.`, 'error');
        return;
    }
    
    if (!confirm(`Delete group "${groupName}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`/kuma/api/groups/${groupId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': csrfToken
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`Group "${groupName}" deleted!`, 'success');
            loadGroupsList();
            // Force full refresh of main data
            await loadData(true);
            showChangesBanner();
        } else {
            showToast(result.error || 'Failed to delete group', 'error');
        }
    } catch (error) {
        console.error('Delete group failed:', error);
        showToast('Failed to delete group', 'error');
    }
}

// =============================================================================
// Delete Monitors Modal
// =============================================================================
function openDeleteMonitorsModal() {
    if (selectedMonitors.size === 0) {
        showToast('Please select monitors to delete first', 'error');
        return;
    }
    
    const modal = document.getElementById('delete-monitors-modal');
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        loadDeleteMonitorsList();
        
        // Reset confirmation
        const confirmCheckbox = document.getElementById('delete-monitors-confirm');
        const confirmBtn = document.getElementById('confirm-delete-btn');
        if (confirmCheckbox) {
            confirmCheckbox.checked = false;
            confirmCheckbox.onchange = () => {
                if (confirmBtn) confirmBtn.disabled = !confirmCheckbox.checked;
            };
        }
        if (confirmBtn) confirmBtn.disabled = true;
    }
}

function closeDeleteMonitorsModal() {
    const modal = document.getElementById('delete-monitors-modal');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
}

function loadDeleteMonitorsList() {
    const container = document.getElementById('delete-monitors-list');
    const countEl = document.getElementById('delete-count');
    
    if (!container) return;
    
    const selectedList = monitors.filter(m => selectedMonitors.has(m.id));
    
    if (countEl) countEl.textContent = selectedList.length;
    
    if (selectedList.length === 0) {
        container.innerHTML = '<div class="empty-state">No monitors selected. Select monitors from the list first.</div>';
        return;
    }
    
    container.innerHTML = selectedList
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(m => `
            <div class="manage-item delete-item">
                <div class="manage-item-info">
                    <span class="manage-item-icon">${m.isGroup ? '📁' : '📡'}</span>
                    <span class="manage-item-name">${escapeHtml(m.name)}</span>
                    ${m.group ? `<span class="manage-item-group">in ${escapeHtml(m.group)}</span>` : ''}
                </div>
            </div>
        `).join('');
}

// =============================================================================
// Changes Banner Notification
// =============================================================================
function showChangesBanner() {
    const banner = document.getElementById('changes-banner');
    if (banner) {
        // Reset info panel state
        const infoPanel = document.getElementById('changes-banner-info');
        if (infoPanel) infoPanel.classList.add('hidden');
        
        // Show banner with animation reset
        banner.classList.remove('hidden');
        banner.style.animation = 'none';
        void banner.offsetWidth; // Force reflow
        banner.style.animation = 'slideInRight 0.3s ease-out';
    }
    
    // Also highlight the reconnect button
    highlightReconnectButton();
}

function hideChangesBanner() {
    const banner = document.getElementById('changes-banner');
    if (banner) {
        banner.classList.add('hidden');
    }
}

function showChangesBannerInfo() {
    const infoPanel = document.getElementById('changes-banner-info');
    if (infoPanel) {
        infoPanel.classList.toggle('hidden');
    }
}

function highlightReconnectButton() {
    const reconnectBtn = document.getElementById('reconnect-btn');
    if (reconnectBtn) {
        reconnectBtn.classList.remove('btn-highlight');
        // Force reflow to restart animation
        void reconnectBtn.offsetWidth;
        reconnectBtn.classList.add('btn-highlight');
        
        // Remove class after animation completes
        setTimeout(() => {
            reconnectBtn.classList.remove('btn-highlight');
        }, 2000);
    }
}

// =============================================================================
// Reconnect to Kuma
// =============================================================================
async function reconnectToKuma() {
    const reconnectBtn = document.getElementById('reconnect-btn');
    if (reconnectBtn) {
        reconnectBtn.disabled = true;
        reconnectBtn.innerHTML = '<span class="loading-spinner-sm"></span> Reconnecting...';
    }
    
    try {
        const response = await fetch('/kuma/api/reconnect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Reconnected successfully! Loading fresh data...', 'success');
            // Update connection status UI to show connected
            updateConnectionStatusUI(true);
            // Also trigger a full status check to ensure consistency
            setTimeout(checkConnectionStatus, 1000);
            // Clear selection and reload all data
            selectedMonitors.clear();
            await loadData(true);
            // Hide the changes banner since we just got fresh data
            hideChangesBanner();
        } else if (result.needs_token) {
            // Need 2FA token - show re-auth modal
            showReauthModal('Reconnection requires a new 2FA token.');
        } else {
            showToast(result.error || 'Reconnection failed', 'error');
        }
    } catch (error) {
        console.error('Reconnect failed:', error);
        showToast('Reconnection failed: ' + error.message, 'error');
    } finally {
        if (reconnectBtn) {
            reconnectBtn.disabled = false;
            reconnectBtn.innerHTML = '🔄 Reconnect';
        }
    }
}

async function confirmDeleteMonitors() {
    const confirmCheckbox = document.getElementById('delete-monitors-confirm');
    if (!confirmCheckbox?.checked) {
        showToast('Please confirm you understand this action is irreversible', 'error');
        return;
    }
    
    const confirmBtn = document.getElementById('confirm-delete-btn');
    if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<span class="loading-spinner-sm"></span> Deleting...';
    }
    
    // Validate connection first
    const connectionValid = await validateConnection();
    if (!connectionValid) {
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '🗑️ Delete Selected Monitors';
        }
        return;
    }
    
    try {
        const response = await fetch('/kuma/api/delete-monitors', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                monitor_ids: Array.from(selectedMonitors)
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            showToast(`Error: ${result.error}`, 'error');
        } else if (result.success !== undefined) {
            if (result.errors > 0) {
                showToast(`Deleted ${result.success} monitor(s), ${result.errors} failed`, 'error');
            } else if (result.success > 0) {
                showToast(`Successfully deleted ${result.success} monitor(s)!`, 'success');
            }
            
            closeDeleteMonitorsModal();
            // Force full refresh of main data
            await loadData(true);
            selectNone();
            showChangesBanner();
        }
    } catch (error) {
        console.error('Delete failed:', error);
        showToast(`Delete failed: ${error.message}`, 'error');
    } finally {
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '🗑️ Delete Selected Monitors';
        }
    }
}

// Store pending operation for retry after re-auth
let pendingOperation = null;

async function applyChanges() {
    if (selectedMonitors.size === 0) {
        showToast('Please select at least one monitor', 'error');
        return;
    }
    
    const changes = buildChanges();
    if (Object.keys(changes).length === 0) {
        showToast('Please select at least one change', 'error');
        return;
    }
    
    const applyBtn = document.getElementById('apply-btn');
    const originalText = applyBtn.textContent;
    applyBtn.disabled = true;
    applyBtn.innerHTML = '<span class="loading-spinner-sm"></span> Validating...';
    
    // Validate connection BEFORE attempting changes
    const connectionValid = await validateConnection();
    if (!connectionValid) {
        // Store pending operation for retry after re-auth
        pendingOperation = {
            type: 'bulk-edit',
            monitorIds: Array.from(selectedMonitors),
            changes: changes
        };
        applyBtn.disabled = false;
        applyBtn.textContent = originalText;
        return; // Re-auth modal already shown by validateConnection
    }
    
    applyBtn.innerHTML = '<span class="loading-spinner-sm"></span> Applying...';
    
    try {
        const response = await fetch('/kuma/api/bulk-edit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                monitor_ids: Array.from(selectedMonitors),
                changes: changes,
                dry_run: false
            })
        });
        
        const result = await response.json();
        
        // Check for session expired / needs re-auth
        if (response.status === 401 && result.session_expired) {
            // Store the pending operation for retry
            pendingOperation = {
                type: 'bulk-edit',
                monitorIds: Array.from(selectedMonitors),
                changes: changes
            };
            
            if (result.needs_token) {
                // Show re-authentication modal
                showReauthModal(result.message || 'Your session has expired. Please enter a new 2FA token.');
            } else {
                // If no token needed (has secret), try auto-reconnect
                showToast('Session expired. Redirecting to reconnect...', 'error');
                setTimeout(() => {
                    window.location.href = '/kuma/disconnect';
                }, 2000);
            }
            return;
        }
        
        
        if (result.error) {
            showToast(`Error: ${result.error}`, 'error');
        } else if (result.success !== undefined) {
            // Show result with success and error counts
            if (result.errors > 0) {
                showToast(`Updated ${result.success} monitor(s), ${result.errors} failed`, 'error');
                if (result.messages && result.messages.length > 0) {
                    console.error('Bulk edit errors:', result.messages);
                }
            } else if (result.success > 0) {
                showToast(`Successfully updated ${result.success} monitor(s)!`, 'success');
            } else {
                showToast('No monitors were updated', 'error');
            }
            
            // Force full refresh and clear selection
            await loadData(true);
            selectNone();
            clearBulkChanges();
            showChangesBanner();
        } else {
            showToast('Unexpected response from server', 'error');
            console.error('Unexpected response:', result);
        }
        
    } catch (error) {
        console.error('[APPLY] Bulk edit failed:', error);
        showToast(`Failed: ${error.message}`, 'error');
    } finally {
        applyBtn.disabled = false;
        applyBtn.textContent = originalText;
    }
}

// =============================================================================
// Connection Validation
// =============================================================================
async function validateConnection() {
    try {
        const response = await fetch('/kuma/api/validate-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });
        const result = await response.json();
        
        if (response.status === 401 && result.expired) {
            // Session expired - update status indicator to red
            updateConnectionStatusUI(false, 'Session expired');
            
            pendingOperation = pendingOperation || { type: 'validate' };
            
            if (result.needs_token) {
                showReauthModal(result.message || 'Your session has expired. Please enter a new 2FA token.');
            } else {
                showToast('Session expired. Redirecting to reconnect...', 'error');
                setTimeout(() => {
                    window.location.href = '/kuma/disconnect';
                }, 2000);
            }
            return false;
        }
        
        if (!result.valid) {
            // Update status indicator to red
            updateConnectionStatusUI(false, result.message || 'Connection error');
            showToast('Connection error: ' + (result.message || 'Unknown error'), 'error');
            return false;
        }
        
        // Connection is valid - ensure status is green
        updateConnectionStatusUI(true);
        return true;
    } catch (error) {
        console.error('Connection validation failed:', error);
        updateConnectionStatusUI(false, 'Connection error');
        showToast('Failed to validate connection', 'error');
        return false;
    }
}

// Update the connection status indicator in the navbar
function updateConnectionStatusUI(isConnected, errorMessage = '') {
    const statusEl = document.getElementById('connection-status');
    const statusDot = document.getElementById('status-dot');
    if (!statusEl) return;
    
    if (isConnected) {
        statusEl.classList.remove('expired', 'disconnected');
        statusEl.classList.add('connected');
        statusEl.title = 'Connected';
        // Force a repaint to ensure CSS is applied
        if (statusDot) {
            statusDot.style.color = '';
            void statusDot.offsetWidth;
        }
    } else {
        statusEl.classList.remove('connected');
        statusEl.classList.add('expired');
        statusEl.title = errorMessage || 'Connection expired';
    }
}

// =============================================================================
// Re-authentication Modal
// =============================================================================
function showReauthModal(message) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('reauth-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'reauth-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content reauth-modal-content">
                <div class="modal-header">
                    <h2>Session Expired</h2>
                </div>
                <div class="modal-body">
                    <div class="reauth-message">
                        <span class="reauth-icon">🔐</span>
                        <p id="reauth-message-text"></p>
                    </div>
                    <div class="form-group">
                        <label for="reauth-totp">Enter New 2FA Token</label>
                        <input type="text" id="reauth-totp" class="form-control" 
                               placeholder="6-digit code" maxlength="6" 
                               autocomplete="one-time-code" inputmode="numeric"
                               pattern="[0-9]{6}">
                        <small class="form-hint">Enter the code from your authenticator app</small>
                    </div>
                    <div id="reauth-error" class="alert alert-error hidden"></div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeReauthModal()">Cancel</button>
                    <button class="btn btn-primary" id="reauth-submit-btn" onclick="submitReauth()">
                        Authenticate
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // Auto-focus and enter key submit
        modal.querySelector('#reauth-totp').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') submitReauth();
        });
    }
    
    // Set message and show modal
    document.getElementById('reauth-message-text').textContent = message;
    document.getElementById('reauth-totp').value = '';
    document.getElementById('reauth-error').classList.add('hidden');
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    
    // Focus on input
    setTimeout(() => {
        document.getElementById('reauth-totp').focus();
    }, 100);
}

function closeReauthModal() {
    const modal = document.getElementById('reauth-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
    }
    pendingOperation = null;
}

async function submitReauth() {
    const totpInput = document.getElementById('reauth-totp');
    const errorEl = document.getElementById('reauth-error');
    const submitBtn = document.getElementById('reauth-submit-btn');
    
    const token = totpInput.value.trim();
    
    // Validate input
    if (!token || !/^\d{6}$/.test(token)) {
        errorEl.textContent = 'Please enter a valid 6-digit code';
        errorEl.classList.remove('hidden');
        totpInput.focus();
        return;
    }
    
    // Show loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading-spinner-sm"></span> Authenticating...';
    errorEl.classList.add('hidden');
    
    try {
        const response = await fetch('/kuma/api/reauth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ totp_token: token })
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            // Close modal
            closeReauthModal();
            showToast('Re-authenticated successfully!', 'success');
            
            // Retry the pending operation
            if (pendingOperation) {
                const opType = pendingOperation.type;
                pendingOperation = null;
                
                // Brief delay to ensure connection is ready
                setTimeout(async () => {
                    if (opType === 'bulk-edit') {
                        showToast('Retrying operation...', 'info');
                        await applyChanges();
                    } else if (opType === 'refresh-notifications') {
                        await refreshNotifications();
                    } else if (opType === 'validate') {
                        // Force full refresh after validation re-auth
                        await loadData(true);
                    }
                }, 500);
            }
        } else {
            // Show error
            errorEl.textContent = result.error || 'Authentication failed. Please try again.';
            errorEl.classList.remove('hidden');
            totpInput.value = '';
            totpInput.focus();
            
            // Check if we need to redirect
            if (result.redirect) {
                setTimeout(() => {
                    window.location.href = '/kuma/connect';
                }, 2000);
            }
        }
        
    } catch (error) {
        console.error('Re-auth failed:', error);
        errorEl.textContent = 'Network error. Please try again.';
        errorEl.classList.remove('hidden');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Authenticate';
    }
}

// Add reauth modal styles
const reauthStyles = document.createElement('style');
reauthStyles.textContent = `
    .reauth-modal-content {
        max-width: 400px;
    }
    .reauth-message {
        text-align: center;
        padding: 1.5rem 0;
    }
    .reauth-icon {
        font-size: 3rem;
        display: block;
        margin-bottom: 1rem;
    }
    .reauth-message p {
        color: var(--text-muted);
        font-size: 0.9375rem;
        line-height: 1.5;
    }
    #reauth-totp {
        text-align: center;
        font-size: 1.5rem;
        letter-spacing: 0.5rem;
        padding: 1rem;
    }
    .form-hint {
        display: block;
        margin-top: 0.5rem;
        color: var(--text-muted);
        font-size: 0.8125rem;
    }
    #reauth-error {
        margin-top: 1rem;
    }
`;
document.head.appendChild(reauthStyles);

// Add small spinner style
const spinnerStyles = document.createElement('style');
spinnerStyles.textContent = `
    .loading-spinner-sm {
        display: inline-block;
        width: 16px;
        height: 16px;
        border: 2px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
        margin-right: 0.5rem;
    }
`;
document.head.appendChild(spinnerStyles);

// =============================================================================
// Mobile Menu
// =============================================================================
function toggleMobileMenu() {
    const menu = document.querySelector('.navbar-menu');
    menu?.classList.toggle('active');
}

// =============================================================================
// Utilities
// =============================================================================
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// Close modal on backdrop click
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        closeModal();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + A to select all (when not in input)
    if ((e.ctrlKey || e.metaKey) && e.key === 'a' && 
        !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        selectAll();
    }
});
