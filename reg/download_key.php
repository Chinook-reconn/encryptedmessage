<?php
// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

function secure_memory_cleanup(&$data) {
    if (is_string($data)) {
        $data = str_repeat("\0", strlen($data));
    }
    unset($data);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key_file'])) {
    $fileName = basename($_POST['key_file']);

    // Strict whitelist: only allow properly named PEM files
    if (!preg_match('/^login-[a-f0-9]{16}-priv\\.pem$/', $fileName)) {
        die("Invalid filename format.");
    }

    $filePath = "/path/to/keys/" . $fileName;

    if (file_exists($filePath)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/x-pem-file');
        header('Content-Disposition: attachment; filename="' . $fileName . '"');
        header('Content-Length: ' . filesize($filePath));
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        header("Content-Security-Policy: default-src 'none';");

        flush();
        readfile($filePath);
        unlink($filePath); // delete after successful download

        secure_memory_cleanup($fileName);
        secure_memory_cleanup($filePath);
        exit;
    } else {
        die("File not found.");
    }
} else {
    die("Invalid request.");
}
