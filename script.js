/* ========================================================
   ENCODEX - COMPREHENSIVE CRYPTOGRAPHY & FEATURES
   ======================================================== */

'use strict';

// ================== CONFIGURATION ==================
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const MESSAGE_EXPIRY_DAYS = 30; // Warning if message older than 30 days

// ================== DOM ELEMENTS ==================
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const copyEncryptedBtn = document.getElementById('copy-encrypted-btn');
const shareEncryptedBtn = document.getElementById('share-encrypted-btn');
const qrEncryptedBtn = document.getElementById('qr-encrypted-btn');
const downloadEncryptedBtn = document.getElementById('download-encrypted-btn');
const copyDecryptedBtn = document.getElementById('copy-decrypted-btn');
const downloadDecryptedBtn = document.getElementById('download-decrypted-btn');

const plaintextInput = document.getElementById('plaintext');
const encryptPassphrase = document.getElementById('encrypt-passphrase');
const encryptedOutput = document.getElementById('encrypted-output');
const encryptedOutputGroup = document.getElementById('encrypted-output-group');

const encryptedInput = document.getElementById('encrypted-input');
const decryptPassphrase = document.getElementById('decrypt-passphrase');
const decryptedOutput = document.getElementById('decrypted-output');
const decryptedOutputGroup = document.getElementById('decrypted-output-group');
const decryptError = document.getElementById('decrypt-error');

const compressOption = document.getElementById('compress-option');
const uploadFileBtn = document.getElementById('upload-file-btn');
const fileInput = document.getElementById('file-input');

const plaintextCounter = document.getElementById('plaintext-counter');
const encryptedCounter = document.getElementById('encrypted-counter');

const qrEncryptContainer = document.getElementById('qr-encrypt-container');
const qrEncryptCode = document.getElementById('qr-encrypt-code');

const messageAgeDiv = document.getElementById('message-age');

const themeToggle = document.getElementById('theme-toggle');
const historySection = document.getElementById('history-section');
const historyList = document.getElementById('history-list');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// Password strength elements
const encryptStrengthBar = document.getElementById('encrypt-strength-bar');
const encryptStrengthText = document.getElementById('encrypt-strength-text');
const decryptStrengthBar = document.getElementById('decrypt-strength-bar');
const decryptStrengthText = document.getElementById('decrypt-strength-text');

// Passphrase generator modal
const passphraseModal = document.getElementById('passphrase-modal');
const generatedPassphrase = document.getElementById('generated-passphrase');
const closeModal = document.getElementById('close-modal');
const regeneratePassBtn = document.getElementById('regenerate-pass-btn');
const copyPassBtn = document.getElementById('copy-pass-btn');
const usePassBtn = document.getElementById('use-pass-btn');
const includeNumbers = document.getElementById('include-numbers');
const includeSymbols = document.getElementById('include-symbols');

let currentPassphraseTarget = null; // Track which field to populate

// ================== CRYPTO HELPER FUNCTIONS ==================

function generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

function arrayBufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ================== COMPRESSION FUNCTIONS ==================

async function compressString(str) {
    const stream = new Blob([str]).stream();
    const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
    const compressedBlob = await new Response(compressedStream).blob();
    const buffer = await compressedBlob.arrayBuffer();
    return new Uint8Array(buffer);
}

async function decompressString(compressedData) {
    const stream = new Blob([compressedData]).stream();
    const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
    const decompressedBlob = await new Response(decompressedStream).blob();
    return await decompressedBlob.text();
}

// ================== ENCRYPTION FUNCTIONS ==================

async function deriveKey(passphrase, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        stringToArrayBuffer(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptMessage(message, passphrase, useCompression = true) {
    if (!message || !passphrase) {
        throw new Error('Message and passphrase are required');
    }
    
    if (passphrase.length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
    }
    
    let dataToEncrypt = message;
    let isCompressed = false;
    
    // Compress if enabled and message is long enough
    if (useCompression && message.length > 100) {
        try {
            const compressed = await compressString(message);
            dataToEncrypt = arrayBufferToBase64(compressed);
            isCompressed = true;
        } catch (err) {
            console.warn('Compression failed, encrypting uncompressed:', err);
        }
    }
    
    const salt = generateRandomBytes(SALT_LENGTH);
    const iv = generateRandomBytes(IV_LENGTH);
    const key = await deriveKey(passphrase, salt);
    
    // Add timestamp and compression flag to metadata
    const timestamp = Date.now();
    const metadata = JSON.stringify({ 
        t: timestamp, 
        c: isCompressed 
    });
    
    // Prepend metadata length and metadata to data
    const metadataBytes = stringToArrayBuffer(metadata);
    const metadataLength = new Uint8Array([metadataBytes.length]);
    const dataBytes = stringToArrayBuffer(dataToEncrypt);
    
    const combined = new Uint8Array(metadataLength.length + metadataBytes.length + dataBytes.length);
    combined.set(metadataLength, 0);
    combined.set(metadataBytes, metadataLength.length);
    combined.set(dataBytes, metadataLength.length + metadataBytes.length);
    
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        combined
    );
    
    const finalCombined = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
    finalCombined.set(salt, 0);
    finalCombined.set(iv, salt.length);
    finalCombined.set(new Uint8Array(encryptedData), salt.length + iv.length);
    
    return arrayBufferToBase64(finalCombined.buffer);
}

async function decryptMessage(encryptedBase64, passphrase) {
    if (!encryptedBase64 || !passphrase) {
        throw new Error('Encrypted message and passphrase are required');
    }
    
    try {
        const combined = base64ToArrayBuffer(encryptedBase64);
        const combinedArray = new Uint8Array(combined);
        
        if (combinedArray.length < SALT_LENGTH + IV_LENGTH + 1) {
            throw new Error('Invalid encrypted data format');
        }
        
        const salt = combinedArray.slice(0, SALT_LENGTH);
        const iv = combinedArray.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const encryptedData = combinedArray.slice(SALT_LENGTH + IV_LENGTH);
        
        const key = await deriveKey(passphrase, salt);
        
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );
        
        const decryptedArray = new Uint8Array(decryptedData);
        const metadataLength = decryptedArray[0];
        const metadataBytes = decryptedArray.slice(1, 1 + metadataLength);
        const dataBytes = decryptedArray.slice(1 + metadataLength);
        
        const metadata = JSON.parse(arrayBufferToString(metadataBytes));
        let message = arrayBufferToString(dataBytes);
        
        // Decompress if needed
        if (metadata.c) {
            try {
                const compressedData = base64ToArrayBuffer(message);
                message = await decompressString(compressedData);
            } catch (err) {
                console.warn('Decompression failed:', err);
            }
        }
        
        // Check message age
        if (metadata.t) {
            const ageInDays = (Date.now() - metadata.t) / (1000 * 60 * 60 * 24);
            if (ageInDays > MESSAGE_EXPIRY_DAYS) {
                showMessageAge(ageInDays);
            }
        }
        
        return message;
        
    } catch (error) {
        throw new Error('Decryption failed: wrong passphrase or corrupted data');
    }
}

// ================== PASSWORD STRENGTH METER ==================

function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (!password) return { score: 0, text: '', className: '' };
    
    // Length
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (password.length >= 16) strength += 1;
    
    // Character variety
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;
    
    if (strength <= 3) {
        return { score: strength, text: '⚠️ Weak', className: 'weak' };
    } else if (strength <= 5) {
        return { score: strength, text: '🔸 Medium', className: 'medium' };
    } else {
        return { score: strength, text: '✅ Strong', className: 'strong' };
    }
}

function updatePasswordStrength(input, barElement, textElement) {
    const strength = calculatePasswordStrength(input.value);
    
    barElement.className = 'strength-bar ' + strength.className;
    textElement.textContent = strength.text;
    textElement.className = 'strength-text ' + strength.className;
}

// ================== PASSPHRASE GENERATOR ==================

const wordList = [
    'Alpha', 'Brave', 'Cloud', 'Delta', 'Eagle', 'Frost', 'Glacier', 'Harbor',
    'Island', 'Jungle', 'Knight', 'Lion', 'Mountain', 'Night', 'Ocean', 'Phoenix',
    'Quest', 'River', 'Storm', 'Thunder', 'Unity', 'Vortex', 'Whisper', 'Xenon',
    'Yellow', 'Zenith', 'Amber', 'Blaze', 'Crystal', 'Dream', 'Eclipse', 'Flame'
];

function generatePassphrase() {
    const numWords = 4;
    const words = [];
    
    for (let i = 0; i < numWords; i++) {
        const randomIndex = Math.floor(Math.random() * wordList.length);
        words.push(wordList[randomIndex]);
    }
    
    let passphrase = words.join('-');
    
    if (includeNumbers.checked) {
        const randomNum = Math.floor(Math.random() * 9000) + 1000;
        passphrase += '-' + randomNum;
    }
    
    if (includeSymbols.checked) {
        const symbols = ['!', '@', '#', '$', '%', '&', '*'];
        const randomSymbol = symbols[Math.floor(Math.random() * symbols.length)];
        passphrase += randomSymbol;
    }
    
    return passphrase;
}

function showPassphraseGenerator(targetField) {
    currentPassphraseTarget = targetField;
    const newPassphrase = generatePassphrase();
    generatedPassphrase.textContent = newPassphrase;
    passphraseModal.style.display = 'flex';
}

// ================== FILE UPLOAD ==================

async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const fileName = file.name.toLowerCase();
    const fileExtension = fileName.split('.').pop();
    
    try {
        // Read file as text
        const text = await file.text();
        
        if (!text || text.trim() === '') {
            alert('⚠️ File is empty');
            fileInput.value = '';
            return;
        }
        
        // Check if the file contains encrypted data (base64-like pattern)
        // Encrypted data is typically long base64 strings
        const trimmedText = text.trim();
        const looksEncrypted = /^[A-Za-z0-9+/=]+$/.test(trimmedText) && trimmedText.length > 200;
        
        if (looksEncrypted) {
            const useAsEncrypted = confirm(
                '🔐 This file appears to contain encrypted data.\n\n' +
                'Click OK to load it into the Decrypt box\n' +
                'Click Cancel to load it as plain text into the Encrypt box'
            );
            
            if (useAsEncrypted) {
                encryptedInput.value = trimmedText;
                encryptedInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                showNotification('✅ Encrypted file loaded into Decrypt box!');
            } else {
                plaintextInput.value = text;
                updateCharCounter(plaintextInput, plaintextCounter);
                showNotification('✅ File loaded into Encrypt box!');
            }
        } else {
            // Regular text file - load into encrypt box
            plaintextInput.value = text;
            updateCharCounter(plaintextInput, plaintextCounter);
            plaintextInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            showNotification(`✅ File "${file.name}" loaded successfully!`);
        }
        
        // Reset file input
        fileInput.value = '';
        
    } catch (error) {
        console.error('File upload error:', error);
        alert('❌ Error reading file: ' + error.message + '\n\nMake sure the file is a text file.');
        fileInput.value = '';
    }
}

// ================== QR CODE GENERATION ==================

function generateQRCode(text) {
    qrEncryptCode.innerHTML = '';
    
    // QR Code has a maximum capacity based on error correction level
    // Using error correction level M allows ~1800 characters
    // Using error correction level L allows ~2900 characters
    const MAX_QR_LENGTH = 2000; // Safe limit for QR codes
    
    if (!text || text.trim() === '') {
        alert('⚠️ No text to generate QR code');
        return;
    }
    
    try {
        // If text is too long, offer chunking or shortened URL option
        if (text.length > MAX_QR_LENGTH) {
            const shouldChunk = confirm(
                `⚠️ Message is ${text.length} characters (max recommended: ${MAX_QR_LENGTH}).\n\n` +
                `Long QR codes may be difficult to scan.\n\n` +
                `Click OK to create multiple QR codes (chunks), or Cancel to try anyway.`
            );
            
            if (shouldChunk) {
                generateChunkedQRCodes(text);
                return;
            }
        }
        
        // Clear previous QR codes
        qrEncryptCode.innerHTML = '';
        
        // Create QR code with appropriate error correction
        // Use lower error correction for longer texts to fit more data
        const errorCorrection = text.length > 1000 ? QRCode.CorrectLevel.L : QRCode.CorrectLevel.M;
        
        new QRCode(qrEncryptCode, {
            text: text,
            width: 300,
            height: 300,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: errorCorrection
        });
        
        qrEncryptContainer.style.display = 'block';
        
        // Add download QR button
        addQRDownloadButton();
        
        showNotification('✅ QR Code generated!');
        
    } catch (error) {
        console.error('QR Code Error:', error);
        alert('❌ Error generating QR code: ' + error.message + '\n\nTry using a shorter message or enable compression.');
    }
}

function generateChunkedQRCodes(text) {
    const CHUNK_SIZE = 1800; // Safe size per QR code
    const chunks = [];
    
    // Split text into chunks
    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        chunks.push(text.substring(i, i + CHUNK_SIZE));
    }
    
    qrEncryptCode.innerHTML = `
        <div style="margin-bottom: 1rem; padding: 1rem; background: rgba(245, 158, 11, 0.1); border-radius: 8px; color: #f59e0b;">
            <strong>📦 Message split into ${chunks.length} parts</strong><br>
            <small>Scan all QR codes in order and combine the text</small>
        </div>
    `;
    
    chunks.forEach((chunk, index) => {
        const chunkContainer = document.createElement('div');
        chunkContainer.style.cssText = `
            margin-bottom: 1.5rem;
            padding: 1rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            text-align: center;
        `;
        
        const label = document.createElement('h5');
        label.textContent = `Part ${index + 1} of ${chunks.length}`;
        label.style.cssText = 'margin-bottom: 0.5rem; color: var(--text-primary);';
        
        const qrDiv = document.createElement('div');
        qrDiv.style.cssText = 'display: inline-block; padding: 1rem; background: white; border-radius: 8px;';
        
        chunkContainer.appendChild(label);
        chunkContainer.appendChild(qrDiv);
        qrEncryptCode.appendChild(chunkContainer);
        
        // Generate QR for this chunk
        new QRCode(qrDiv, {
            text: chunk,
            width: 250,
            height: 250,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });
    });
    
    qrEncryptContainer.style.display = 'block';
    showNotification(`✅ Generated ${chunks.length} QR codes!`);
}

function addQRDownloadButton() {
    // Check if download button already exists
    if (document.getElementById('download-qr-btn')) return;
    
    const downloadBtn = document.createElement('button');
    downloadBtn.id = 'download-qr-btn';
    downloadBtn.className = 'btn btn-secondary btn-small';
    downloadBtn.innerHTML = '💾 Download QR Code';
    downloadBtn.style.cssText = 'margin-top: 1rem;';
    
    downloadBtn.addEventListener('click', () => {
        const qrImage = qrEncryptCode.querySelector('img');
        if (qrImage) {
            const link = document.createElement('a');
            link.download = 'encodex-qr-code.png';
            link.href = qrImage.src;
            link.click();
            showNotification('✅ QR Code downloaded!');
        }
    });
    
    qrEncryptContainer.appendChild(downloadBtn);
}

// ================== TEMPLATES ==================

const templates = {
    note: `📝 SECURE NOTE

Content: [Your confidential note here]

Date: ${new Date().toLocaleDateString()}
`,
    password: `🔐 PASSWORD SHARE

Service: [Service name]
Username: [Username]
Password: [Password]
Notes: [Additional notes]

⚠️ Delete this message after saving!
`,
    meeting: `📅 MEETING INFO

Title: [Meeting title]
Date: [Date and time]
Location: [Physical/Virtual location]
Access Code: [If applicable]
Agenda: [Meeting agenda]

Confidential - Do not forward
`,
    custom: ''
};

// ================== HISTORY MANAGEMENT ==================

let encryptionHistory = [];

function addToHistory(message, encrypted) {
    const historyItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleString(),
        preview: message.substring(0, 50) + (message.length > 50 ? '...' : ''),
        message: message,
        encrypted: encrypted
    };
    
    encryptionHistory.unshift(historyItem);
    
    if (encryptionHistory.length > 10) {
        encryptionHistory = encryptionHistory.slice(0, 10);
    }
    
    renderHistory();
}

function renderHistory() {
    if (encryptionHistory.length === 0) {
        historySection.style.display = 'none';
        return;
    }
    
    historySection.style.display = 'block';
    historyList.innerHTML = '';
    
    encryptionHistory.forEach(item => {
        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        historyItem.innerHTML = `
            <div class="history-item-header">
                <strong>🔒 Encrypted Message</strong>
                <span class="history-time">${item.timestamp}</span>
            </div>
            <div class="history-preview">${item.preview}</div>
        `;
        
        historyItem.addEventListener('click', () => {
            encryptedInput.value = item.encrypted;
            encryptedInput.scrollIntoView({ behavior: 'smooth' });
        });
        
        historyList.appendChild(historyItem);
    });
}

function clearHistory() {
    encryptionHistory = [];
    renderHistory();
    showNotification('🗑️ History cleared');
}

// ================== UTILITY FUNCTIONS ==================

function updateCharCounter(textarea, counterElement) {
    const count = textarea.value.length;
    counterElement.textContent = `${count} characters`;
}

function showMessageAge(ageInDays) {
    const days = Math.floor(ageInDays);
    messageAgeDiv.innerHTML = `⚠️ Warning: This message is ${days} days old. It may be outdated.`;
    messageAgeDiv.style.display = 'block';
}

function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function shareContent(text, title = 'Encrypted Message') {
    if (navigator.share) {
        try {
            await navigator.share({
                title: title,
                text: text
            });
        } catch (error) {
            if (error.name !== 'AbortError') {
                fallbackCopy(text);
            }
        }
    } else {
        fallbackCopy(text);
    }
}

async function fallbackCopy(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('📋 Copied to clipboard!');
    } catch (error) {
        alert('❌ Could not copy to clipboard');
    }
}

function showNotification(message) {
    // Simple notification - could be enhanced with a toast system
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: rgba(99, 102, 241, 0.9);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        z-index: 3000;
        animation: slideInRight 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ================== EVENT HANDLERS ==================

async function handleEncrypt() {
    const message = plaintextInput.value.trim();
    const passphrase = encryptPassphrase.value;
    
    if (!message) {
        alert('⚠️ Please enter a message to encrypt');
        plaintextInput.focus();
        return;
    }
    
    if (!passphrase) {
        alert('⚠️ Please enter a passphrase');
        encryptPassphrase.focus();
        return;
    }
    
    if (passphrase.length < 8) {
        alert('⚠️ Passphrase must be at least 8 characters for security');
        encryptPassphrase.focus();
        return;
    }
    
    try {
        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<span class="btn-text">⏳ Encrypting...</span>';
        
        const encrypted = await encryptMessage(message, passphrase, compressOption.checked);
        
        encryptedOutput.value = encrypted;
        encryptedOutputGroup.style.display = 'block';
        updateCharCounter(encryptedOutput, encryptedCounter);
        
        // Add to history
        addToHistory(message, encrypted);
        
        setTimeout(() => {
            plaintextInput.value = '';
            encryptPassphrase.value = '';
            updateCharCounter(plaintextInput, plaintextCounter);
            updatePasswordStrength(encryptPassphrase, encryptStrengthBar, encryptStrengthText);
        }, 500);
        
        encryptBtn.disabled = false;
        encryptBtn.innerHTML = '<span class="btn-text">✓ Encrypted!</span>';
        setTimeout(() => {
            encryptBtn.innerHTML = '<span class="btn-text">Encrypt</span>';
        }, 2000);
        
    } catch (error) {
        alert('❌ Encryption error: ' + error.message);
        encryptBtn.disabled = false;
        encryptBtn.innerHTML = '<span class="btn-text">Encrypt</span>';
    }
}

async function handleDecrypt() {
    const encrypted = encryptedInput.value.trim();
    const passphrase = decryptPassphrase.value;
    
    decryptError.style.display = 'none';
    decryptedOutputGroup.style.display = 'none';
    messageAgeDiv.style.display = 'none';
    
    if (!encrypted) {
        showDecryptError('⚠️ Please paste an encrypted message');
        encryptedInput.focus();
        return;
    }
    
    if (!passphrase) {
        showDecryptError('⚠️ Please enter the passphrase');
        decryptPassphrase.focus();
        return;
    }
    
    try {
        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<span class="btn-text">⏳ Decrypting...</span>';
        
        const decrypted = await decryptMessage(encrypted, passphrase);
        
        decryptedOutput.value = decrypted;
        decryptedOutputGroup.style.display = 'block';
        
        setTimeout(() => {
            encryptedInput.value = '';
            decryptPassphrase.value = '';
            updatePasswordStrength(decryptPassphrase, decryptStrengthBar, decryptStrengthText);
        }, 500);
        
        decryptBtn.disabled = false;
        decryptBtn.innerHTML = '<span class="btn-text">✓ Decrypted!</span>';
        setTimeout(() => {
            decryptBtn.innerHTML = '<span class="btn-text">Decrypt</span>';
        }, 2000);
        
    } catch (error) {
        showDecryptError('❌ ' + error.message);
        decryptBtn.disabled = false;
        decryptBtn.innerHTML = '<span class="btn-text">Decrypt</span>';
    }
}

function showDecryptError(message) {
    decryptError.textContent = message;
    decryptError.style.display = 'block';
}

// ================== EVENT LISTENERS ==================

// Main buttons
encryptBtn.addEventListener('click', handleEncrypt);
decryptBtn.addEventListener('click', handleDecrypt);

// Copy buttons
if (copyEncryptedBtn) {
    copyEncryptedBtn.addEventListener('click', async () => {
        await fallbackCopy(encryptedOutput.value);
    });
}

if (copyDecryptedBtn) {
    copyDecryptedBtn.addEventListener('click', async () => {
        await fallbackCopy(decryptedOutput.value);
    });
}

// Share button
if (shareEncryptedBtn) {
    shareEncryptedBtn.addEventListener('click', async () => {
        await shareContent(encryptedOutput.value, 'ENCODEX - Encrypted Message');
    });
}

// QR Code button
if (qrEncryptedBtn) {
    qrEncryptedBtn.addEventListener('click', () => {
        generateQRCode(encryptedOutput.value);
    });
}

// QR Close button
const qrCloseBtn = document.getElementById('qr-close-btn');
if (qrCloseBtn) {
    qrCloseBtn.addEventListener('click', () => {
        qrEncryptContainer.style.display = 'none';
    });
}

// Download buttons
if (downloadEncryptedBtn) {
    downloadEncryptedBtn.addEventListener('click', () => {
        downloadFile(encryptedOutput.value, 'encrypted-message.txt');
    });
}

if (downloadDecryptedBtn) {
    downloadDecryptedBtn.addEventListener('click', () => {
        downloadFile(decryptedOutput.value, 'decrypted-message.txt');
    });
}

// File upload
if (uploadFileBtn && fileInput) {
    uploadFileBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileUpload);
}

// Character counters
plaintextInput.addEventListener('input', () => {
    updateCharCounter(plaintextInput, plaintextCounter);
});

encryptedOutput.addEventListener('input', () => {
    updateCharCounter(encryptedOutput, encryptedCounter);
});

// Password strength meters
encryptPassphrase.addEventListener('input', () => {
    updatePasswordStrength(encryptPassphrase, encryptStrengthBar, encryptStrengthText);
});

decryptPassphrase.addEventListener('input', () => {
    updatePasswordStrength(decryptPassphrase, decryptStrengthBar, decryptStrengthText);
});

// Show/Hide password toggles
document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const input = document.getElementById(targetId);
        
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '🙈';
        } else {
            input.type = 'password';
            btn.textContent = '👁️';
        }
    });
});

// Passphrase generator buttons
document.getElementById('generate-encrypt-pass').addEventListener('click', () => {
    showPassphraseGenerator('encrypt-passphrase');
});

document.getElementById('generate-decrypt-pass').addEventListener('click', () => {
    showPassphraseGenerator('decrypt-passphrase');
});

regeneratePassBtn.addEventListener('click', () => {
    const newPassphrase = generatePassphrase();
    generatedPassphrase.textContent = newPassphrase;
});

copyPassBtn.addEventListener('click', async () => {
    await fallbackCopy(generatedPassphrase.textContent);
});

usePassBtn.addEventListener('click', () => {
    if (currentPassphraseTarget) {
        const input = document.getElementById(currentPassphraseTarget);
        input.value = generatedPassphrase.textContent;
        
        // Update strength meter
        if (currentPassphraseTarget === 'encrypt-passphrase') {
            updatePasswordStrength(input, encryptStrengthBar, encryptStrengthText);
        } else {
            updatePasswordStrength(input, decryptStrengthBar, decryptStrengthText);
        }
    }
    passphraseModal.style.display = 'none';
});

closeModal.addEventListener('click', () => {
    passphraseModal.style.display = 'none';
});

// Close modal on outside click
passphraseModal.addEventListener('click', (e) => {
    if (e.target === passphraseModal) {
        passphraseModal.style.display = 'none';
    }
});

// Templates
document.querySelectorAll('.template-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.template-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        const template = btn.getAttribute('data-template');
        plaintextInput.value = templates[template];
        updateCharCounter(plaintextInput, plaintextCounter);
    });
});

// Theme toggle
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
    const icon = themeToggle.querySelector('.theme-icon');
    
    if (document.body.classList.contains('light-mode')) {
        icon.textContent = '☀️';
        localStorage.setItem('theme', 'light');
    } else {
        icon.textContent = '🌙';
        localStorage.setItem('theme', 'dark');
    }
});

// Load saved theme
const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'light') {
    document.body.classList.add('light-mode');
    themeToggle.querySelector('.theme-icon').textContent = '☀️';
}

// History
if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', clearHistory);
}

// Enter key shortcuts
encryptPassphrase.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleEncrypt();
});

decryptPassphrase.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleDecrypt();
});

// Clear sensitive data on page unload
window.addEventListener('beforeunload', () => {
    plaintextInput.value = '';
    encryptPassphrase.value = '';
    encryptedInput.value = '';
    decryptPassphrase.value = '';
    encryptedOutput.value = '';
    decryptedOutput.value = '';
    encryptionHistory = [];
});

// Prevent context menu on password fields (optional security)
document.querySelectorAll('input[type="password"]').forEach(input => {
    input.addEventListener('contextmenu', (e) => e.preventDefault());
});

// Initialize
console.log('🔐 ENCODEX loaded - All operations are 100% client-side');
console.log('✨ Features: Encryption, Compression, QR Codes, Templates, History & More!');

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
    }
`;
document.head.appendChild(style);