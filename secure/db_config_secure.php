<?php
// db_config_secure.php - Secure PDO Database Connection configuration

// Simple environment loader fallback if composer autoload isn't active
function load_env_file($path) {
    if (file_exists($path)) {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }
            if (strpos($line, '=') !== false) {
                list($name, $value) = explode('=', $line, 2);
                $name = trim($name);
                $value = trim($value);
                // Strip quotes if present
                if (preg_match('/^"([^"]*)"$/', $value, $matches) || preg_match("/^'([^']*)'$/", $value, $matches)) {
                    $value = $matches[1];
                }
                if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                    putenv(sprintf('%s=%s', $name, $value));
                    $_ENV[$name] = $value;
                    $_SERVER[$name] = $value;
                }
            }
        }
    }
}

// Load environment variables from project root .env
load_env_file(__DIR__ . '/../.env');

$host = getenv('DB_HOST') ?: '127.0.0.1';
$port = getenv('DB_PORT') ?: '3306';
$db   = getenv('DB_DATABASE') ?: 'medic_vault_db';
// Enforce low-privilege user credentials for secure context
$user = getenv('DB_USERNAME') ?: 'medic_staff';
$pass = getenv('DB_PASSWORD') ?: 'MedicStaffSecurePassword123!';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;port=$port;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    // Disable emulation of prepared statements to prevent edge-case SQL injections
    PDO::ATTR_EMULATE_PREPARES   => false,
];

if (!defined('TESTING_MODE')) {
    try {
        $pdo = new PDO($dsn, $user, $pass, $options);
    } catch (\PDOException $e) {
        // Prevent information disclosure: do not output raw exception details (like username/passwords/directories)
        error_log("Database connection failure: " . $e->getMessage());
        header('HTTP/1.1 500 Internal Server Error');
        die("Error: A secure database connection error occurred. Please contact the administrator.");
    }
}

?>
