document.addEventListener('DOMContentLoaded', function () {
    const rulesTableContainer = document.getElementById('rulesTableContainer');
    const addRuleBtn = document.getElementById('addRuleBtn');

    if (addRuleBtn) {
        addRuleBtn.addEventListener('click', function () {
            window.location.href = '/rule/create-ui/';
        });
    }

    function fetchRules() {
        fetch('/rules/')
            .then(res => {
                if (!res.ok) throw new Error('Network error: ' + res.status);
                return res.json();
            })
            .then(data => {
                renderRulesTable(data.rules);
            })
            .catch(err => {
                // Optionally handle error silently or show a user-friendly message
            });
    }


    function renderRulesTable(rules) {
        if (!rules.length) {
            rulesTableContainer.innerHTML = '<div style="text-align:center;color:#aeb4c6;">No rules yet. Click + to add one.</div>';
            return;
        }
        let html = '<table class="table"><thead><tr>' +
            '<th>Name</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
        for (const rule of rules) {
            html += `<tr class="rule-row" data-id="${rule.id}" style="cursor: pointer;">
                <td>${rule.rule_name}</td>
                <td>
                    <label class="toggle-switch">
                        <input type="checkbox" data-id="${rule.id}" class="toggle-enabled" ${rule.enabled ? 'checked' : ''}>
                        <span class="toggle-slider"></span>
                    </label>
                </td>
                <td>
                    <button class="action-btn edit-btn" data-id="${rule.id}">✏️</button>
                    <button class="action-btn delete-btn" data-id="${rule.id}">🗑️</button>
                </td>
            </tr>`;
        }
        html += '</tbody></table>';
        rulesTableContainer.innerHTML = html;
        attachTableEvents();
    }


    function attachTableEvents() {
        // Row Click
        document.querySelectorAll('.rule-row').forEach(el => {
            el.addEventListener('click', function (e) {
                // Prevent navigation if text was selected
                if (window.getSelection().toString().length > 0) return;
                window.location.href = `/rule/${el.dataset.id}/edit-ui/`;
            });
        });

        // Toggle Switch (prevent row open on any toggle click)
        document.querySelectorAll('.toggle-switch, .toggle-enabled, .toggle-slider').forEach(el => {
            el.addEventListener('click', function (e) {
                e.stopPropagation();
            });
        });
        document.querySelectorAll('.toggle-enabled').forEach(el => {
            el.addEventListener('change', function (e) {
                fetch(`/rule/${el.dataset.id}/toggle/`, { method: 'POST', headers: { 'X-CSRFToken': getCookie('csrftoken') } })
                    .then(() => fetchRules());
            });
        });

        // Edit Button (Redundant with row click, but keep for explicit action)
        document.querySelectorAll('.edit-btn').forEach(el => {
            el.addEventListener('click', function (e) {
                e.stopPropagation();
                window.location.href = `/rule/${el.dataset.id}/edit-ui/`;
            });
        });

        // Delete Button
        document.querySelectorAll('.delete-btn').forEach(el => {
            el.addEventListener('click', function (e) {
                e.stopPropagation(); // Prevent row click
                if (confirm('Delete this rule?')) {
                    fetch(`/rule/${el.dataset.id}/delete/`, { method: 'POST', headers: { 'X-CSRFToken': getCookie('csrftoken') } })
                        .then(() => fetchRules());
                }
            });
        });
    }

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    fetchRules();
});
