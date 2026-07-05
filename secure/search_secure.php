<?php
// search_secure.php - Patient & Medical Record Search Proxy (Secure Version)
require_once 'db_config_secure.php';

// Ensure keyword parameter is present and validate/sanitize input
if (!isset($_GET['keyword']) || $_GET['keyword'] === '') {
    header('HTTP/1.1 400 Bad Request');
    die("Error: Missing search keyword.");
}

$keyword = $_GET['keyword'];

// Sanitize and secure output variables
$safeKeyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');

try {
    // FIX SQL Injection: Use parameterized query
    $sql = "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :keyword";
    $stmt = $pdo->prepare($sql);
    
    // Bind parameter with wildcards
    $likeKeyword = "%" . $keyword . "%";
    $stmt->execute([':keyword' => $likeKeyword]);
    $results = $stmt->fetchAll();

    if (count($results) > 0) {
        foreach ($results as $row) {
            // FIX Reflected XSS: Context-specific HTML encoding
            $safeName = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
            $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8');
            
            echo "<div>Result found for keyword: " . $safeKeyword . "<br>";
            echo "Patient: " . $safeName . " | History: " . $safeHistory . "</div><hr>";
        }
    } else {
        // FIX Reflected XSS: Context-specific HTML encoding
        echo "No records found for: " . $safeKeyword;
    }
} catch (\PDOException $e) {
    // Hide DB exception information from public output, log it locally
    error_log("Search SQL execution failure: " . $e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    die("Error: Search process failed securely.");
}
?>
