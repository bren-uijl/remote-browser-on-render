document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const resultFrame = document.getElementById('resultFrame');
    const statusDiv = document.getElementById('status');

    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            statusDiv.textContent = 'Please enter a URL.';
            return;
        }
        // Set the iframe source to the fetch route to display the fetched page
        statusDiv.textContent = 'Loading page...';
        resultFrame.src = `/fetch?url=${encodeURIComponent(url)}`;
        statusDiv.textContent = '';
    });
});
