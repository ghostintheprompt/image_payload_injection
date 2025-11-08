// ImageGuard - Advanced Image Security Analyzer
// Main Application JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize elements
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const previewImage = document.getElementById('preview-image');
    const uploadPrompt = document.getElementById('upload-prompt');
    const analyzeButton = document.getElementById('analyze-button');
    const sanitizeButton = document.getElementById('sanitize-button');
    const loadingSpinner = document.getElementById('loading-spinner');
    const resultsArea = document.getElementById('results-area');
    const batchFileInput = document.getElementById('batch-file-input');
    const batchAnalyzeButton = document.getElementById('batch-analyze-button');
    const batchFileList = document.getElementById('batch-file-list');

    // Register Service Worker for PWA
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/static/sw.js').then(function(registration) {
            console.log('ServiceWorker registered:', registration.scope);
        }).catch(function(error) {
            console.log('ServiceWorker registration failed:', error);
        });
    }

    // Drag and drop handlers
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => uploadArea.classList.add('dragging'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => uploadArea.classList.remove('dragging'), false);
    });

    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFiles(files[0]);
        }
    }

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFiles(e.target.files[0]);
        }
    });

    function handleFiles(file) {
        resetResults();

        // Preview image
        const reader = new FileReader();
        reader.onload = function(e) {
            previewImage.src = e.target.result;
            previewImage.classList.remove('hidden');
            uploadPrompt.classList.add('hidden');
        };
        reader.readAsDataURL(file);

        // Enable buttons
        analyzeButton.disabled = false;
        sanitizeButton.disabled = false;
    }

    function resetResults() {
        document.getElementById('analysis-results').classList.add('hidden');
        document.getElementById('sanitization-results').classList.add('hidden');
        document.getElementById('batch-results').classList.add('hidden');
        document.getElementById('file-info').innerHTML = '';
        document.getElementById('threats-container').innerHTML = '';
        document.getElementById('sanitization-message').innerHTML = '';
        document.getElementById('download-area').classList.add('hidden');
        resultsArea.classList.add('hidden');
    }

    // Analyze Image
    analyzeButton.addEventListener('click', () => {
        if (fileInput.files.length === 0) return;

        loadingSpinner.classList.remove('hidden');
        resultsArea.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            loadingSpinner.classList.add('hidden');
            resultsArea.classList.remove('hidden');
            displayAnalysisResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loadingSpinner.classList.add('hidden');
            showError('Error analyzing image: ' + error);
        });
    });

    function displayAnalysisResults(data) {
        const analysisResults = document.getElementById('analysis-results');
        const fileInfo = document.getElementById('file-info');
        const threatsContainer = document.getElementById('threats-container');
        const riskBadge = document.getElementById('risk-badge');

        fileInfo.innerHTML = '';
        threatsContainer.innerHTML = '';

        // Set risk badge
        riskBadge.textContent = data.risk_level;
        riskBadge.className = 'risk-badge';

        if (data.risk_level === 'High') {
            riskBadge.classList.add('risk-high');
        } else if (data.risk_level === 'Medium') {
            riskBadge.classList.add('risk-medium');
        } else {
            riskBadge.classList.add('risk-low');
        }

        // Display file info
        let fileInfoHtml = '<h6 class="mb-3"><strong>📄 File Information</strong></h6><dl class="row mb-0 small">';
        for (const [key, value] of Object.entries(data.file_info)) {
            if (key !== 'unique_id') {
                const formattedKey = formatKey(key);
                fileInfoHtml += `<dt class="col-5">${formattedKey}:</dt><dd class="col-7">${value}</dd>`;
            }
        }
        fileInfoHtml += '</dl>';
        fileInfo.innerHTML = fileInfoHtml;

        // Display threats
        for (const [threatName, threatInfo] of Object.entries(data.threats)) {
            const isDetected = threatInfo[0];
            const details = threatInfo[1];

            const threatDiv = document.createElement('div');
            threatDiv.className = 'threat-item ' + (isDetected ? 'threat-detected' : 'threat-safe');

            const threatTitle = document.createElement('h6');
            threatTitle.className = 'mb-1';
            threatTitle.innerHTML = `<strong>${isDetected ? '⚠️ ' : '✅ '}${formatThreatName(threatName)}</strong>`;
            threatDiv.appendChild(threatTitle);

            if (isDetected && details) {
                const detailsText = document.createElement('p');
                detailsText.className = 'mb-0 small text-muted';
                detailsText.textContent = details;
                threatDiv.appendChild(detailsText);
            } else if (!isDetected) {
                const safeText = document.createElement('p');
                safeText.className = 'mb-0 small text-muted';
                safeText.textContent = 'No threats detected';
                threatDiv.appendChild(safeText);
            }

            threatsContainer.appendChild(threatDiv);
        }

        analysisResults.classList.remove('hidden');
    }

    function formatThreatName(threatName) {
        return threatName
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    function formatKey(key) {
        return key
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    // Sanitize Image
    sanitizeButton.addEventListener('click', () => {
        if (fileInput.files.length === 0) return;

        loadingSpinner.classList.remove('hidden');
        resultsArea.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('remove_metadata', document.getElementById('remove-metadata').checked);
        formData.append('sanitize_svg', document.getElementById('sanitize-svg').checked);

        const formatConversion = document.getElementById('format-conversion').value;
        if (formatConversion) {
            formData.append('format_conversion', formatConversion);
        }

        const maxWidth = document.getElementById('max-width').value;
        const maxHeight = document.getElementById('max-height').value;
        if (maxWidth && maxHeight) {
            formData.append('max_width', maxWidth);
            formData.append('max_height', maxHeight);
        }

        fetch('/sanitize', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            loadingSpinner.classList.add('hidden');
            resultsArea.classList.remove('hidden');
            displaySanitizationResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loadingSpinner.classList.add('hidden');
            showError('Error sanitizing image: ' + error);
        });
    });

    function displaySanitizationResults(data) {
        const sanitizationResults = document.getElementById('sanitization-results');
        const sanitizationMessage = document.getElementById('sanitization-message');
        const downloadArea = document.getElementById('download-area');
        const downloadLink = document.getElementById('download-link');
        const sanitizedPreview = document.getElementById('sanitized-preview');

        if (data.success) {
            sanitizationMessage.innerHTML = `<strong>✅ Success!</strong> ${data.message}`;
            sanitizationMessage.className = 'alert alert-success';

            downloadLink.href = data.download_url;
            downloadLink.download = `sanitized_${data.original_filename}`;

            sanitizedPreview.src = data.download_url;
            sanitizedPreview.classList.remove('hidden');

            downloadArea.classList.remove('hidden');
        } else {
            sanitizationMessage.innerHTML = `<strong>❌ Error!</strong> ${data.message || data.error}`;
            sanitizationMessage.className = 'alert alert-danger';
            downloadArea.classList.add('hidden');
        }

        sanitizationResults.classList.remove('hidden');
    }

    // Batch Processing
    batchFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            batchAnalyzeButton.disabled = false;

            batchFileList.innerHTML = '';
            for (let i = 0; i < e.target.files.length; i++) {
                const file = e.target.files[i];
                const fileItem = document.createElement('div');
                fileItem.className = 'batch-file-item';
                fileItem.innerHTML = `
                    <strong>${file.name}</strong>
                    <small class="d-block text-muted">${formatFileSize(file.size)}</small>
                `;
                batchFileList.appendChild(fileItem);
            }
        } else {
            batchAnalyzeButton.disabled = true;
            batchFileList.innerHTML = '';
        }
    });

    batchAnalyzeButton.addEventListener('click', () => {
        if (batchFileInput.files.length === 0) return;

        loadingSpinner.classList.remove('hidden');
        resultsArea.classList.add('hidden');

        const formData = new FormData();
        for (let i = 0; i < batchFileInput.files.length; i++) {
            formData.append('files[]', batchFileInput.files[i]);
        }

        fetch('/batch_analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            loadingSpinner.classList.add('hidden');
            resultsArea.classList.remove('hidden');
            displayBatchResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loadingSpinner.classList.add('hidden');
            showError('Error analyzing batch: ' + error);
        });
    });

    function displayBatchResults(data) {
        const batchResults = document.getElementById('batch-results');
        const batchSummary = document.getElementById('batch-summary');
        const batchAccordion = document.getElementById('batch-results-accordion');

        batchSummary.innerHTML = `<strong>📊 Batch Analysis Complete!</strong> Analyzed ${data.file_count} file(s)`;

        batchAccordion.innerHTML = '';

        let fileIndex = 0;
        for (const [filename, results] of Object.entries(data.results)) {
            const accordionItem = document.createElement('div');
            accordionItem.className = 'accordion-item';

            const header = document.createElement('h2');
            header.className = 'accordion-header';
            header.id = `heading-${fileIndex}`;

            const button = document.createElement('button');
            button.className = 'accordion-button collapsed';
            button.type = 'button';
            button.setAttribute('data-bs-toggle', 'collapse');
            button.setAttribute('data-bs-target', `#collapse-${fileIndex}`);

            if (results.risk_level) {
                const riskClass = results.risk_level === 'High' ? 'danger' :
                                  results.risk_level === 'Medium' ? 'warning' : 'success';
                button.innerHTML = `<span class="flex-grow-1">${filename}</span> <span class="badge bg-${riskClass} ms-2">${results.risk_level}</span>`;
            } else if (results.error) {
                button.innerHTML = `<span class="flex-grow-1">${filename}</span> <span class="badge bg-danger ms-2">Error</span>`;
            } else {
                button.textContent = filename;
            }

            header.appendChild(button);
            accordionItem.appendChild(header);

            const collapseDiv = document.createElement('div');
            collapseDiv.id = `collapse-${fileIndex}`;
            collapseDiv.className = 'accordion-collapse collapse';
            collapseDiv.setAttribute('data-bs-parent', '#batch-results-accordion');

            const body = document.createElement('div');
            body.className = 'accordion-body';

            if (results.error) {
                body.innerHTML = `<div class="alert alert-danger">${results.error}</div>`;
            } else {
                let fileInfoHtml = '<h6 class="mb-3">File Information</h6><dl class="row mb-3 small">';
                for (const [key, value] of Object.entries(results.file_info)) {
                    if (key !== 'unique_id') {
                        fileInfoHtml += `<dt class="col-4">${formatKey(key)}:</dt><dd class="col-8">${value}</dd>`;
                    }
                }
                fileInfoHtml += '</dl>';

                let threatsHtml = '<h6 class="mb-3">Security Findings</h6>';
                for (const [threatName, threatInfo] of Object.entries(results.threats)) {
                    const isDetected = threatInfo[0];
                    const details = threatInfo[1];

                    threatsHtml += `<div class="threat-item ${isDetected ? 'threat-detected' : 'threat-safe'}">`;
                    threatsHtml += `<strong>${isDetected ? '⚠️ ' : '✅ '}${formatThreatName(threatName)}</strong>`;

                    if (isDetected && details) {
                        threatsHtml += `<p class="mb-0 small text-muted">${details}</p>`;
                    }

                    threatsHtml += '</div>';
                }

                body.innerHTML = fileInfoHtml + threatsHtml;
            }

            collapseDiv.appendChild(body);
            accordionItem.appendChild(collapseDiv);
            batchAccordion.appendChild(accordionItem);

            fileIndex++;
        }

        document.getElementById('analysis-results').classList.add('hidden');
        document.getElementById('sanitization-results').classList.add('hidden');
        batchResults.classList.remove('hidden');
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) {
            return bytes + ' B';
        } else if (bytes < 1024 * 1024) {
            return (bytes / 1024).toFixed(2) + ' KB';
        } else {
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        }
    }

    function showError(message) {
        alert(message);
    }
});
