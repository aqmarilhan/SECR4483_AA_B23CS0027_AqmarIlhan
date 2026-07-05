<?php
// db_config.php - High privilege database connection configuration
// Inadvertently running under root access and default settings.

$host = '127.0.0.1';
$db   = 'medic_vault_db';
$user = 'root';
$pass = ''; // Default XAMPP empty password

// Create connection if not in testing mode
if (!defined('TESTING_MODE')) {
    $conn = new mysqli($host, $user, $pass, $db);

    // Check connection
    if ($conn->connect_error) {
        // In production, exposing raw connection errors is a disclosure vulnerability
        die("Connection failed: " . $conn->connect_error);
    }
}

?>
