const dropArea = document.getElementById('dropArea');
const fileInput = document.getElementById('fileInput');
const progressBar = document.getElementById('progress-bar');
const progressContainer = document.getElementById('progress-container');
progressBar.textContent = '';
progressContainer.dataset.progress = '0%';

dropArea.addEventListener('click', () => fileInput.click());

dropArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropArea.classList.add('dragover');
});

dropArea.addEventListener('dragleave', () => {
    dropArea.classList.remove('dragover');
});

dropArea.addEventListener('drop', (e) => {
    e.preventDefault();
    dropArea.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        uploadFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
        uploadFile(fileInput.files[0]);
    }
});

function setProgressText(text) {
    progressContainer.dataset.progress = text;
}

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    const csrfEl = document.getElementById('csrfToken');
    if (csrfEl) {
        formData.append('csrf_token', csrfEl.value);
    }

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload', true);

    xhr.upload.onprogress = function (e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percent + '%';
            setProgressText(percent + '%');
        }
    };

    xhr.onload = function () {
        if (xhr.status === 200) {
            setProgressText('Done');
            setTimeout(() => location.reload(), 1000);
        } else {
            setProgressText('Error');
        }
    };

    xhr.onerror = function () {
        setProgressText('Error');
    };

    xhr.send(formData);
}

document.addEventListener('DOMContentLoaded', () => {
    const origin = window.location.origin;
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', () => {
            const filename = button.getAttribute('data-filename');
            const url = origin + '/' + filename;

            // Create a temporary element for copying
            const textArea = document.createElement('textarea');
            textArea.value = url;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);

            button.classList.add('copied');
            setTimeout(() => button.classList.remove('copied'), 1500);
        });
    });
});

document.querySelectorAll('.file-button').forEach(btn => {
    btn.addEventListener('click', function (e) {
        if (e.target.closest('.copy-btn')) return;
        const url = this.dataset.url;
        window.open(url, '_blank');
    });
});