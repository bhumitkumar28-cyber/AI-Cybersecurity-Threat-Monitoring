document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initDashboard();
    
    // Add event listeners for dynamic interactions
    setupEventListeners();
});

function initDashboard() {
    // Set up charts and initial data
    console.log('Dashboard initialized');
}

function setupEventListeners() {
    // General buttons
    document.querySelectorAll('.btn').forEach(button => {

        // AI prediction button ko ignore karo
        if (button.id === 'predictThreatBtn') {
            return;
        }

        button.addEventListener('click', function() {

            if (this.classList.contains('btn-primary')) {
                this.innerHTML =
                    '<i class="fas fa-spinner fa-spin"></i> Processing...';
            }

        });
    });
}
// Function to format dates
function formatDate(dateString) {
    const date = new Date(dateString);
    const options = { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return date.toLocaleDateString('en-US', options);
}

// Function to show toast notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas ${type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

// Add toast styles dynamically
const toastStyles = document.createElement('style');
toastStyles.textContent = `
.toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    padding: 15px 20px;
    min-width: 250px;
    z-index: 1000;
    transform: translateY(100px);
    transition: transform 0.3s ease;
}

.toast.show {
    transform: translateY(0);
}

.toast-content {
    display: flex;
    align-items: center;
    gap: 10px;
}

.toast-content i {
    font-size: 1.2rem;
}

.toast-info .toast-content i { color: #3498db; }
.toast-success .toast-content i { color: #27ae60; }
.toast-error .toast-content i { color: #e74c3c; }
`;
document.head.appendChild(toastStyles);
function connectThreatWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';

    const socket = new WebSocket(
        `${protocol}://${window.location.host}/ws/threats/`
    );

    socket.onopen = function () {
        console.log('Real-time threat monitoring connected.');
    };

    socket.onmessage = function (event) {
        const threat = JSON.parse(event.data);

        showToast(
            `${threat.severity}: ${threat.type}`,
            threat.severity === 'CRITICAL' ? 'error' : 'info'
        );

        if (threat.severity === 'CRITICAL') {
            alert(
                `CRITICAL SECURITY ALERT\n\n` +
                `${threat.type}\n\n${threat.description}`
            );
        }

        setTimeout(() => {
            window.location.reload();
        }, 1200);
    };

    socket.onclose = function () {
        console.warn('WebSocket disconnected. Retrying in 5 seconds.');
        setTimeout(connectThreatWebSocket, 5000);
    };
}

document.addEventListener('DOMContentLoaded', function () {
    initDashboard();
    setupEventListeners();
    connectThreatWebSocket();
});