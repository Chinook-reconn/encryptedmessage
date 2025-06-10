<?php
// === Disable caching to protect sensitive file ===
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// === Secure memory cleanup function ===
function secure_memory_cleanup(&$data) {
    if (is_string($data)) {
        $data = str_repeat("\0", strlen($data));
    }
    unset($data);
}

// === Logging for debugging ===
$logFile = '/var/www/html/mess_keys/mkey-delete.txt';
file_put_contents($logFile, "=== Download Attempt ===\n", FILE_APPEND);
file_put_contents($logFile, "Method: {$_SERVER['REQUEST_METHOD']}\n", FILE_APPEND);
file_put_contents($logFile, "key_file: " . ($_POST['key_file'] ?? 'NOT SET') . "\n", FILE_APPEND);

// === Handle only POST requests with expected key_file ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key_file'])) {
    $fileName = basename($_POST['key_file']);


    // === Strict filename validation (mess-<random>-priv.key) ===
    if (!preg_match('/^mess-[a-f0-9]{20}-priv\.key$/', $fileName)) {
        file_put_contents($logFile, "Regex validation failed for: $fileName\n", FILE_APPEND);
        die("❌ Invalid key filename format.");
    }

    $filePath = "/var/www/html/mess_keys/" . $fileName;

    // === Check file existence and serve it ===
    if (file_exists($filePath)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $fileName . '"');
        header('Content-Length: ' . filesize($filePath));
        header("Content-Security-Policy: default-src 'none';");

        flush();
        readfile($filePath);

        // Delete the file after download to confirm delivery
        unlink($filePath);

        // Optional: also delete .sig file if it exists
        $sigPath = $filePath . '.sig';
        if (file_exists($sigPath)) {
            unlink($sigPath);
        }

        // Secure memory cleanup
        secure_memory_cleanup($fileName);
        secure_memory_cleanup($filePath);
        exit;
    } else {
        file_put_contents($logFile, "File not found: $filePath\n", FILE_APPEND);
        die("Key file not found or already downloaded.");
    }
} else {
    file_put_contents($logFile, "Invalid request — missing POST or key_file\n", FILE_APPEND);
    die("Invalid request.");
}
?>
