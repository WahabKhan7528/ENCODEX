/* ========================================================
   SECURE ENCRYPT - CRYPTOGRAPHY IMPLEMENTATION
   ========================================================
   
   ENCRYPTION PROCESS:
   1. User enters plaintext message and a passphrase
   2. Generate random 16-byte salt
   3. Derive 256-bit AES key from passphrase using PBKDF2 (100,000 iterations)
   4. Generate random 12-byte IV (Initialization Vector)
   5. Encrypt message with AES-GCM-256
   6. Combine: salt + iv + encrypted data → Base64 encode
   
   DECRYPTION PROCESS:
   1. User enters encrypted Base64 string and passphrase
   2. Decode Base64 to extract: salt, iv, encrypted data
   3. Derive the same 256-bit key from passphrase + salt
   4. Decrypt using AES-GCM with the IV
   5. If passphrase is wrong or data is tampered, decryption fails
   
   SECURITY FEATURES:
   - AES-GCM provides authenticated encryption (integrity + confidentiality)
   - Random salt prevents rainbow table attacks on passphrase
   - Random IV ensures same message encrypts differently each time
   - PBKDF2 with 100k iterations makes brute-force attacks costly
   - Web Crypto API is cryptographically secure and browser-native
   
   NO DATA IS EVER:
   - Sent to any server
   - Stored in localStorage/sessionStorage
   - Logged to console (in production)
   - Transmitted over network
   
   ======================================================== */

'use strict';

// ================== DOM ELEMENTS ==================
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const copyEncryptedBtn = document.getElementById('copy-encrypted-btn');

const plaintextInput = document.getElementById('plaintext');
const encryptPassphrase = document.getElementById('encrypt-passphrase');
const encryptedOutput = document.getElementById('encrypted-output');
const encryptedOutputGroup = document.getElementById('encrypted-output-group');

const encryptedInput = document.getElementById('encrypted-input');
const decryptPassphrase = document.getElementById('decrypt-passphrase');
const decryptedOutput = document.getElementById('decrypted-output');
const decryptedOutputGroup = document.getElementById('decrypted-output-group');
const decryptError = document.getElementById('decrypt-error');

// ================== CRYPTO CONFIGURATION ==================
const PBKDF2_ITERATIONS = 100000; // Number of PBKDF2 iterations (higher = more secure but slower)
const SALT_LENGTH = 16; // 16 bytes = 128 bits
const IV_LENGTH = 12; // 12 bytes = 96 bits (recommended for GCM)

// ================== HELPER FUNCTIONS ==================

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
function generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert string to ArrayBuffer for crypto operations
 * @param {string} str - Input string
 * @returns {ArrayBuffer}
 */
function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

/**
 * Convert ArrayBuffer to string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ================== CRYPTOGRAPHIC FUNCTIONS ==================

/**
 * Derive an AES-GCM key from a passphrase using PBKDF2
 * @param {string} passphrase - User's secret passphrase
 * @param {Uint8Array} salt - Random salt
 * @returns {Promise<CryptoKey>} Derived encryption key
 */
async function deriveKey(passphrase, salt) {
    // Import passphrase as raw key material
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        stringToArrayBuffer(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    // Derive AES-GCM key using PBKDF2
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 }, // 256-bit AES key
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt a message using AES-GCM
 * @param {string} message - Plaintext message
 * @param {string} passphrase - Encryption passphrase
 * @returns {Promise<string>} Base64-encoded encrypted data (salt + iv + ciphertext)
 */
async function encryptMessage(message, passphrase) {
    // Input validation
    if (!message || !passphrase) {
        throw new Error('Message and passphrase are required');
    }
    
    if (passphrase.length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
    }
    
    // Generate random salt and IV
    const salt = generateRandomBytes(SALT_LENGTH);
    const iv = generateRandomBytes(IV_LENGTH);
    
    // Derive encryption key from passphrase
    const key = await deriveKey(passphrase, salt);
    
    // Encrypt the message
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        stringToArrayBuffer(message)
    );
    
    // Combine salt + iv + encrypted data into single buffer
    const combined = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encryptedData), salt.length + iv.length);
    
    // Return as Base64 string for easy transmission
    return arrayBufferToBase64(combined.buffer);
}

/**
 * Decrypt a message using AES-GCM
 * @param {string} encryptedBase64 - Base64-encoded encrypted data
 * @param {string} passphrase - Decryption passphrase
 * @returns {Promise<string>} Decrypted plaintext message
 */
async function decryptMessage(encryptedBase64, passphrase) {
    // Input validation
    if (!encryptedBase64 || !passphrase) {
        throw new Error('Encrypted message and passphrase are required');
    }
    
    try {
        // Decode Base64 to ArrayBuffer
        const combined = base64ToArrayBuffer(encryptedBase64);
        const combinedArray = new Uint8Array(combined);
        
        // Validate minimum length (salt + iv + at least some ciphertext)
        if (combinedArray.length < SALT_LENGTH + IV_LENGTH + 1) {
            throw new Error('Invalid encrypted data format');
        }
        
        // Extract salt, iv, and encrypted data
        const salt = combinedArray.slice(0, SALT_LENGTH);
        const iv = combinedArray.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const encryptedData = combinedArray.slice(SALT_LENGTH + IV_LENGTH);
        
        // Derive decryption key from passphrase (must match encryption key)
        const key = await deriveKey(passphrase, salt);
        
        // Decrypt the data
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );
        
        // Convert decrypted ArrayBuffer back to string
        return arrayBufferToString(decryptedData);
        
    } catch (error) {
        // Decryption fails if:
        // - Wrong passphrase used
        // - Data has been tampered with (GCM authentication fails)
        // - Invalid format
        throw new Error('Decryption failed: wrong passphrase or corrupted data');
    }
}

// ================== UI HANDLERS ==================

/**
 * Handle encryption button click
 */
async function handleEncrypt() {
    const message = plaintextInput.value.trim();
    const passphrase = encryptPassphrase.value;
    
    // Validate inputs
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
        // Show loading state
        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<span class="btn-text">⏳ Encrypting...</span>';
        
        // Perform encryption
        const encrypted = await encryptMessage(message, passphrase);
        
        // Display result
        encryptedOutput.value = encrypted;
        encryptedOutputGroup.style.display = 'block';
        
        // Clear sensitive inputs for security
        setTimeout(() => {
            plaintextInput.value = '';
            encryptPassphrase.value = '';
        }, 500);
        
        // Reset button
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

/**
 * Handle decryption button click
 */
async function handleDecrypt() {
    const encrypted = encryptedInput.value.trim();
    const passphrase = decryptPassphrase.value;
    
    // Clear previous error
    decryptError.style.display = 'none';
    decryptedOutputGroup.style.display = 'none';
    
    // Validate inputs
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
        // Show loading state
        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<span class="btn-text">⏳ Decrypting...</span>';
        
        // Perform decryption
        const decrypted = await decryptMessage(encrypted, passphrase);
        
        // Display result
        decryptedOutput.value = decrypted;
        decryptedOutputGroup.style.display = 'block';
        
        // Clear sensitive inputs
        setTimeout(() => {
            encryptedInput.value = '';
            decryptPassphrase.value = '';
        }, 500);
        
        // Reset button
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

/**
 * Show decryption error message
 * @param {string} message - Error message to display
 */
function showDecryptError(message) {
    decryptError.textContent = message;
    decryptError.style.display = 'block';
}

/**
 * Copy encrypted output to clipboard
 */
async function handleCopyEncrypted() {
    const text = encryptedOutput.value;
    
    if (!text) {
        return;
    }
    
    try {
        await navigator.clipboard.writeText(text);
        
        // Show feedback
        copyEncryptedBtn.innerHTML = '✓ Copied!';
        setTimeout(() => {
            copyEncryptedBtn.innerHTML = '📋 Copy to Clipboard';
        }, 2000);
        
    } catch (error) {
        // Fallback for older browsers
        encryptedOutput.select();
        document.execCommand('copy');
        
        copyEncryptedBtn.innerHTML = '✓ Copied!';
        setTimeout(() => {
            copyEncryptedBtn.innerHTML = '📋 Copy to Clipboard';
        }, 2000);
    }
}

// ================== EVENT LISTENERS ==================

encryptBtn.addEventListener('click', handleEncrypt);
decryptBtn.addEventListener('click', handleDecrypt);
copyEncryptedBtn.addEventListener('click', handleCopyEncrypted);

// Allow Enter key to trigger encryption/decryption
encryptPassphrase.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleEncrypt();
    }
});

decryptPassphrase.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleDecrypt();
    }
});

// ================== SECURITY MEASURES ==================

// Prevent any form of auto-save or caching
window.addEventListener('beforeunload', () => {
    // Clear all sensitive fields
    plaintextInput.value = '';
    encryptPassphrase.value = '';
    encryptedInput.value = '';
    decryptPassphrase.value = '';
    encryptedOutput.value = '';
    decryptedOutput.value = '';
});

// Disable right-click context menu on password fields (optional security measure)
document.querySelectorAll('input[type="password"]').forEach(input => {
    input.addEventListener('contextmenu', (e) => {
        e.preventDefault();
    });
});

// Log app ready message (can be removed in production)
console.log('🔐 Secure Encrypt loaded - All operations are 100% client-side');
console.log('⚠️ Never share your passphrase through the same channel as encrypted data');
