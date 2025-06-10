<?php
// Secure memory cleanup
function secure_memory_cleanup(&$var) {
    if (is_string($var)) {
        $var = str_repeat("\0", strlen($var));
    }
    unset($var);
}

$logFile = '/path/to/log/delete-check.txt'; //monitoring key deletation

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Invalid method for cleanup\n", FILE_APPEND);
    exit("Method Not Allowed");
}

$keyFile = basename($_POST['key_file'] ?? '');
$nickname = $_POST['nickname'] ?? '';
$username = $_POST['username'] ?? '';

if (!preg_match('/^login-[a-f0-9]{16}-priv\\.pem$/', $keyFile)) {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Invalid key filename: $keyFile\n", FILE_APPEND);
    exit("Invalid filename.");
}

$filePath = "/path/to/keys/$keyFile";

if (file_exists($filePath)) {
    if (unlink($filePath)) {
        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Deleted key: $keyFile (nickname: $nickname)\n", FILE_APPEND);
    } else {
        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Failed to delete key: $keyFile\n", FILE_APPEND);
    }
} else {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] File not found for deletion: $keyFile\n", FILE_APPEND);
}

require_once '/path/to/secure-helper.php';
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
if ($redis->auth(MMDC_REDIS_PASS)) {
    $redisKey = "reg:$nickname";
    $redis->del($redisKey);
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Redis cleanup attempted for $redisKey\n", FILE_APPEND);
}

secure_memory_cleanup($keyFile);
secure_memory_cleanup($nickname);
secure_memory_cleanup($username);
secure_memory_cleanup($filePath);
secure_memory_cleanup($redisKey);
unset($redis);

exit("Cleanup complete");
