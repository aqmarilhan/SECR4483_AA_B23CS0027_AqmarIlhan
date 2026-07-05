<?php
// crypto_vault_secure.php - Patient Medical Records Symmetric Protection (Secure AEAD Version)
require_once 'db_config_secure.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['payload']) || $_POST['payload'] === '') {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Invalid or missing payload."]);
        exit;
    }
    
    $medical_payload = $_POST['payload'];

    try {
        // FIX Cryptographic Key Hardcoding:
        // Load the key from environment configuration (.env)
        $hex_key = getenv('CRYPTO_VAULT_KEY');
        if (!$hex_key || strlen($hex_key) !== 64 || !ctype_xdigit($hex_key)) {
            throw new Exception("Cryptographic key is unconfigured or invalid.");
        }
        $secret_key = hex2bin($hex_key);

        // FIX Insecure Symmetric Block Cipher: Upgrade AES-128-ECB to AES-256-GCM (AEAD mode)
        // 1. Manually initialize and generate a 12-byte IV using a CSPRNG (openssl_random_pseudo_bytes)
        $iv_length = 12;
        $crypto_strong = false;
        $iv = openssl_random_pseudo_bytes($iv_length, $crypto_strong);
        
        if ($iv === false || !$crypto_strong || strlen($iv) !== $iv_length) {
            throw new Exception("Initialization Vector generation failed or was cryptographically weak.");
        }

        // 2. Bound constraints on input payload length to prevent resource exhaustion
        if (strlen($medical_payload) > 50000) { // e.g. 50KB maximum size for medical record payload
            throw new Exception("Payload size exceeds maximum allowed boundary.");
        }

        // 3. Perform encryption and explicitly bind the Authentication Tag
        $tag = '';
        $tag_length = 16; // Standard 16-byte authentication tag for AES-GCM
        
        // Use OPENSSL_RAW_DATA to return raw bytes, allowing clean base64 output package construction
        $encrypted = openssl_encrypt(
            $medical_payload,
            'aes-256-gcm',
            $secret_key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '', // No Associated Data (AAD) used here
            $tag_length
        );

        if ($encrypted === false) {
            throw new Exception("Symmetric encryption operation failed.");
        }

        // Return secure vaulted payload containing base64 encoded ciphertext, IV, and tag
        echo json_encode([
            "status" => "vaulted",
            "data" => base64_encode($encrypted),
            "iv" => base64_encode($iv),
            "tag" => base64_encode($tag)
        ]);

    } catch (Exception $e) {
        // Log the actual error internally and return a generic error message
        error_log("Encryption failure: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Secure vaulting operation failed."]);
    }
} else {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed."]);
}
?>
