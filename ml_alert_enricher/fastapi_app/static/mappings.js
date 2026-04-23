// fastapi_app/static/mappings.js
document.addEventListener('DOMContentLoaded', function() {
    loadMappings();

    // Form submission
    document.getElementById('mapping-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const data = {
            okta_user_email: formData.get('okta_user_email'),
            wazuh_agent_id: formData.get('wazuh_agent_id'),
            cloud_pc_id: formData.get('cloud_pc_id') || null,
            is_vip: formData.get('is_vip') === 'on'
        };

        fetch('/add-mapping', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            showStatusMessage('Mapping added/updated successfully!', 'success');
            document.getElementById('mapping-form').reset();
            loadMappings();
        })
        .catch(error => {
            showStatusMessage('Error adding mapping: ' + error.message, 'error');
        });
    });

    // Cancel button
    document.getElementById('cancel-btn').addEventListener('click', function() {
        document.getElementById('mapping-form').reset();
        document.getElementById('form-title').textContent = 'Add New Mapping';
        document.getElementById('submit-btn').textContent = 'Add Mapping';
        this.style.display = 'none';
    });

    // Modal functionality
    const modal = document.getElementById('edit-modal');
    const closeBtn = document.querySelector('.close');

    closeBtn.onclick = function() {
        modal.style.display = 'none';
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }

    // Edit form submission
    document.getElementById('edit-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const agentId = document.getElementById('edit_agent_id').value;
        const formData = new FormData(this);
        const data = {
            okta_user_email: formData.get('okta_user_email'),
            wazuh_agent_id: agentId,
            cloud_pc_id: formData.get('edit_cloud_pc_id') || null,
            is_vip: formData.get('edit_is_vip') === 'on'
        };

        fetch(`/mappings/${agentId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            showStatusMessage('Mapping updated successfully!', 'success');
            modal.style.display = 'none';
            loadMappings();
        })
        .catch(error => {
            showStatusMessage('Error updating mapping: ' + error.message, 'error');
        });
    });

    // Edit cancel button
    document.getElementById('edit-cancel-btn').addEventListener('click', function() {
        modal.style.display = 'none';
    });
});

function loadMappings() {
    fetch('/mappings')
        .then(response => response.json())
        .then(mappings => {
            const tbody = document.getElementById('mappings-tbody');
            tbody.innerHTML = '';

            if (mappings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No mappings found</td></tr>';
                return;
            }

            mappings.forEach(mapping => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${mapping.wazuh_agent_id}</td>
                    <td>${mapping.okta_user_email}</td>
                    <td>${mapping.cloud_pc_id || '-'}</td>
                    <td>${mapping.is_vip ? '✓' : '-'}</td>
                    <td>
                        <button onclick="editMapping('${mapping.wazuh_agent_id}')" class="btn-edit">Edit</button>
                        <button onclick="deleteMapping('${mapping.wazuh_agent_id}')" class="btn-delete">Delete</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(error => {
            showStatusMessage('Error loading mappings: ' + error.message, 'error');
        });
}

function editMapping(agentId) {
    fetch(`/mappings/${agentId}`)
        .then(response => response.json())
        .then(mapping => {
            document.getElementById('edit_agent_id').value = mapping.wazuh_agent_id;
            document.getElementById('edit_okta_user_email').value = mapping.okta_user_email;
            document.getElementById('edit_cloud_pc_id').value = mapping.cloud_pc_id || '';
            document.getElementById('edit_is_vip').checked = mapping.is_vip;

            document.getElementById('edit-modal').style.display = 'block';
        })
        .catch(error => {
            showStatusMessage('Error loading mapping: ' + error.message, 'error');
        });
}

function deleteMapping(agentId) {
    if (confirm(`Are you sure you want to delete the mapping for agent ${agentId}?`)) {
        fetch(`/mappings/${agentId}`, {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(result => {
            showStatusMessage('Mapping deleted successfully!', 'success');
            loadMappings();
        })
        .catch(error => {
            showStatusMessage('Error deleting mapping: ' + error.message, 'error');
        });
    }
}

function showStatusMessage(message, type) {
    const statusDiv = document.getElementById('status-message');
    statusDiv.textContent = message;
    statusDiv.className = type;
    statusDiv.style.display = 'block';

    setTimeout(() => {
        statusDiv.style.display = 'none';
    }, 5000);
}