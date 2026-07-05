<?php
// auth_secure.php - Staff Key Authentication System (Secure Version)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['auth_key']) || !is_string($_POST['auth_key'])) {
        header('HTTP/1.1 400 Bad Request');
        die("Error: Invalid or missing authentication key.");
    }
    
    $inputKey = $_POST['auth_key'];
    
    // FIX Defective Bound Constraint Logic:
    // 1. Enforce strict character-length bounds to handle multi-byte characters correctly.
    // 2. Enforce byte-length bounds (e.g. max 128 bytes) to mitigate CPU-exhaustion DoS attacks
    //    inherent in password hashing algorithms (like bcrypt) when processing extremely large inputs.
    $maxChars = 128;
    $maxBytes = 256;
    
    if (mb_strlen($inputKey, 'UTF-8') > $maxChars || strlen($inputKey) > $maxBytes) {
        // Prevent detailed error leakage, return generic secure error
        header('HTTP/1.1 400 Bad Request');
        if (defined('TESTING_MODE')) {
            throw new \Exception("Error: Authentication key violates length constraints.");
        }
        die("Error: Authentication key violates length constraints.");
    }

    // FIX Obsolete Cryptographic Primitive:
    // Upgrade MD5 to standard Argon2id hash representation of the password 'test'
    // '$argon2id$v=19$m=65536,t=4,p=1$v+oQdd+cirZ5mnUfZKqxBg$y4kyzlbgdOEpzGT84DnPHC8znjhdBRZAML+WGRtw6OA' is a valid Argon2id hash of 'test'
    $stored_hash = '$argon2id$v=19$m=65536,t=4,p=1$v+oQdd+cirZ5mnUfZKqxBg$y4kyzlbgdOEpzGT84DnPHC8znjhdBRZAML+WGRtw6OA';
    
    // password_verify is timing-attack resistant and handles the salt extraction automatically
    if (password_verify($inputKey, $stored_hash)) {
        echo "Access Granted.";
    } else {
        // Mitigation: Artificially delay responses or use rate-limiting to prevent brute force
        usleep(100000); // 100ms artificial delay to slow down automated scripts
        header('HTTP/1.1 401 Unauthorized');
        echo "Access Denied.";
    }
} else {
    header('HTTP/1.1 405 Method Not Allowed');
    die("Error: Only POST requests are allowed.");
}
?>
