<?php
// tests/SecurityTest.php

use PHPUnit\Framework\TestCase;

// Define TESTING_MODE globally for tests so database connections are mocked/skipped
if (!defined('TESTING_MODE')) {
    define('TESTING_MODE', true);
}

class SecurityTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset/clean global arrays for each test run
        $_GET = [];
        $_POST = [];
        $_SERVER = [];
        putenv("CRYPTO_VAULT_KEY");
    }

    // =========================================================================
    // SECTION 1: DATABASE SEARCH & SQL INJECTION / XSS TESTS
    // =========================================================================

    /**
     * Test that the vulnerable search script constructs SQL query using concatenation
     * and fails to escape user input (Reflected XSS).
     */
    public function testVulnerableSearchHasSecurityFlaws(): void
    {
        $code = file_get_contents(__DIR__ . '/../vulnerable/search.php');
        
        // Assert SQL Injection signature: string concatenation with GET parameter
        $this->assertStringContainsString('LIKE \'%" . $keyword . "%\'', $code, 
            "Vulnerability Check: vulnerable/search.php must contain raw string concatenation in SQL.");

        // Assert Reflected XSS signatures: echoing raw keyword
        $this->assertStringContainsString('Result found for keyword: " . $keyword', $code, 
            "Vulnerability Check: vulnerable/search.php must echo raw search term in results.");
        $this->assertStringContainsString('"No records found for: " . $keyword', $code, 
            "Vulnerability Check: vulnerable/search.php must echo raw search term in error output.");
    }

    /**
     * Test that secure search script uses prepared statements and escapes outputs.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureSearchMitigations(): void
    {
        $code = file_get_contents(__DIR__ . '/../secure/search_secure.php');

        // Assert SQL Injection mitigation: uses prepare statement
        $this->assertStringContainsString('prepare($sql)', $code, 
            "Security Fix Check: secure/search_secure.php must use prepared statements.");

        // Assert Reflected XSS mitigations: uses HTML escaping
        $this->assertStringContainsString('htmlspecialchars($keyword, ENT_QUOTES, \'UTF-8\')', $code, 
            "Security Fix Check: secure/search_secure.php must escape keyword.");
        $this->assertStringContainsString('htmlspecialchars($row[\'name\']', $code, 
            "Security Fix Check: secure/search_secure.php must escape data from database on output.");
    }

    /**
     * Test secure search script execution with a mock PDO database connection.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureSearchExecutionWithMockDb(): void
    {
        // 1. Setup mock PDO and PDOStatement
        $mockStmt = $this->createMock(\PDOStatement::class);
        $mockStmt->expects($this->once())
                 ->method('execute')
                 ->with([':keyword' => '%John%'])
                 ->willReturn(true);
        $mockStmt->expects($this->once())
                 ->method('fetchAll')
                 ->willReturn([
                     ['id' => 1, 'name' => 'John Doe', 'illness_history' => 'DIAGNOSIS: Stage-2 Carcinoma']
                 ]);

        $mockPdo = $this->createMock(\PDO::class);
        $mockPdo->expects($this->once())
                ->method('prepare')
                ->with($this->stringContains('SELECT id, name, illness_history FROM patient_records WHERE name LIKE :keyword'))
                ->willReturn($mockStmt);

        // Inject the mock PDO object globally before executing secure script
        global $pdo;
        $pdo = $mockPdo;

        // Set search parameters
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET['keyword'] = 'John';

        // Capture output
        ob_start();
        include __DIR__ . '/../secure/search_secure.php';
        $output = ob_get_clean();

        // Verify HTML output contains properly rendered safe results
        $this->assertStringContainsString('Result found for keyword: John', $output);
        $this->assertStringContainsString('Patient: John Doe', $output);
        $this->assertStringContainsString('History: DIAGNOSIS: Stage-2 Carcinoma', $output);
    }

    // =========================================================================
    // SECTION 2: AUTHENTICATION & PASSWORD HASHING TESTS
    // =========================================================================

    /**
     * Test that the vulnerable authentication script uses MD5 hashing.
     */
    public function testVulnerableAuthHasSecurityFlaws(): void
    {
        $code = file_get_contents(__DIR__ . '/../vulnerable/auth.php');
        
        // Assert MD5 primitive usage
        $this->assertStringContainsString('md5($inputKey) === $stored_hash', $code, 
            "Vulnerability Check: vulnerable/auth.php must use obsolete md5 hashing primitive.");
        
        // Assert defective boundary checks
        $this->assertStringContainsString('strlen($inputKey) > 256', $code, 
            "Vulnerability Check: vulnerable/auth.php uses incorrect boundary check logic.");
    }

    /**
     * Test vulnerable authentication execution with correct key.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testVulnerableAuthSuccess(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['auth_key'] = 'test';

        ob_start();
        include __DIR__ . '/../vulnerable/auth.php';
        $output = ob_get_clean();

        $this->assertEquals("Access Granted.", $output);
    }

    /**
     * Test secure authentication execution with correct key.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureAuthSuccess(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['auth_key'] = 'test';

        ob_start();
        include __DIR__ . '/../secure/auth_secure.php';
        $output = ob_get_clean();

        $this->assertEquals("Access Granted.", $output);
    }

    /**
     * Test secure authentication execution with incorrect key.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureAuthFailure(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['auth_key'] = 'wrongpassword';

        ob_start();
        include __DIR__ . '/../secure/auth_secure.php';
        $output = ob_get_clean();

        $this->assertEquals("Access Denied.", $output);
    }

    /**
     * Test secure authentication boundary constraint checking (large multi-byte payload).
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureAuthBoundaryValidation(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        // Generate an input key that is 129 multi-byte characters (violates limits)
        $_POST['auth_key'] = str_repeat('汉', 129); 

        $thrown = false;
        try {
            ob_start();
            include __DIR__ . '/../secure/auth_secure.php';
            ob_get_clean();
        } catch (\Exception $e) {
            $thrown = true;
            $this->assertStringContainsString("violates length constraints", $e->getMessage());
        }
        $this->assertTrue($thrown, "Expected length constraints exception was not thrown.");
    }

    // =========================================================================
    // SECTION 3: SYMMETRIC CRYPTOGRAPHY & CRYPTO VAULT TESTS
    // =========================================================================

    /**
     * Test that the vulnerable crypto vault uses AES-128-ECB block cipher.
     */
    public function testVulnerableCryptoVaultHasSecurityFlaws(): void
    {
        $code = file_get_contents(__DIR__ . '/../vulnerable/crypto_vault.php');
        
        // Assert ECB mode usage and hardcoded key
        $this->assertStringContainsString('aes-128-ecb', $code, 
            "Vulnerability Check: vulnerable/crypto_vault.php must use weak ECB cipher mode.");
        $this->assertStringContainsString('"MedVaultKey123!"', $code, 
            "Vulnerability Check: vulnerable/crypto_vault.php contains hardcoded symmetric key.");
    }

    /**
     * Test secure cryptographic vault encryption and verify AEAD integrity.
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSecureCryptoVaultEncryptionAndDecryption(): void
    {
        // Set environment variables for the secure script
        $keyHex = "d7b5680adfb46e1e8a4a58ffbc327b8849b2512f4585c51480de3e1c6a7b700f";
        putenv("CRYPTO_VAULT_KEY=" . $keyHex);
        $_ENV['CRYPTO_VAULT_KEY'] = $keyHex;

        $payload = "DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Chemotherapy cycle 1. STATUS: Critical.";
        
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['payload'] = $payload;

        ob_start();
        include __DIR__ . '/../secure/crypto_vault_secure.php';
        $output = ob_get_clean();

        $response = json_decode($output, true);
        
        // 1. Verify JSON structure
        $this->assertEquals("vaulted", $response['status']);
        $this->assertArrayHasKey('data', $response);
        $this->assertArrayHasKey('iv', $response);
        $this->assertArrayHasKey('tag', $response);

        // 2. Decode the response parts
        $ciphertext = base64_decode($response['data']);
        $iv = base64_decode($response['iv']);
        $tag = base64_decode($response['tag']);

        // 3. Verify bounds of initialization vector and tag (12-byte IV, 16-byte tag)
        $this->assertEquals(12, strlen($iv), "Secure Fix Check: IV must be exactly 12 bytes.");
        $this->assertEquals(16, strlen($tag), "Secure Fix Check: Authentication tag must be exactly 16 bytes.");

        // 4. Verify that data can be decrypted using the IV and tag (verifying the AEAD binding)
        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            hex2bin($keyHex),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $this->assertEquals($payload, $decrypted, "Security Fix Check: Decrypted message does not match original plaintext.");
    }
}
