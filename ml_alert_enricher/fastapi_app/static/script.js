// fastapi_app/static/script.js
document.addEventListener('DOMContentLoaded', function() {
    const configForm = document.getElementById('config-form');
    const statusMessage = document.getElementById('status-message');
    const submitBtn = document.getElementById('submit-btn');
    const authMethodInput = document.getElementById('auth_method');
    
    const options = document.querySelectorAll('.option');
    const formSections = document.querySelectorAll('.form-section');

    // Function to switch between forms
    function switchForm(selectedOption) {
        // Update selection visual
        options.forEach(opt => opt.classList.remove('selected'));
        selectedOption.classList.add('selected');

        // Show/hide form sections
        const formId = selectedOption.dataset.form;
        formSections.forEach(section => {
            if (section.id === formId) {
                section.style.display = 'block';
            } else {
                section.style.display = 'none';
            }
        });
        
        // Update hidden input with auth method
        if (formId === 'form-no-security') {
            authMethodInput.value = 'no_security';
        } else if (formId === 'form-ssl') {
            authMethodInput.value = 'ssl';
        } else if (formId === 'form-api-key') {
            authMethodInput.value = 'api_key';
        }
    }

    // Add click listeners to options
    options.forEach(option => {
        option.addEventListener('click', () => switchForm(option));
    });

    // Initialize with the first option selected
    switchForm(document.getElementById('option-no-security'));

    // Handle form submission
    configForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        const authMethod = authMethodInput.value;
        let config = { auth_method: authMethod };

        // Collect data from the currently active form section
        if (authMethod === 'no_security') {
            config.host = document.getElementById('host-no-security').value;
            config.port = parseInt(document.getElementById('port-no-security').value, 10);
        } else if (authMethod === 'ssl') {
            config.host = document.getElementById('host-ssl').value;
            config.port = parseInt(document.getElementById('port-ssl').value, 10);
            config.username = document.getElementById('username').value;
            config.password = document.getElementById('password').value;
        } else if (authMethod === 'api_key') {
            config.host = document.getElementById('host-api').value;
            config.api_key = document.getElementById('api_key').value;
        }

        submitBtn.textContent = 'Saving...';
        submitBtn.disabled = true;

        try {
            const response = await fetch('/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            const result = await response.json();
            statusMessage.className = response.ok ? 'success' : 'error';
            statusMessage.textContent = result.message || result.detail;

        } catch (error) {
            statusMessage.className = 'error';
            statusMessage.textContent = 'An unknown error occurred.';
        } finally {
            submitBtn.textContent = 'Save Configuration';
            submitBtn.disabled = false;
        }
    });
});
