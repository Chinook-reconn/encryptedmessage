<?php
// Secure memory cleanup
function secure_memory_cleanup(&$var) {
    if (is_string($var)) {
        $var = str_repeat("\0", strlen($var));
    }
    unset($var);
}

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

require '/path/to/config.php';
require '/path/to/secure-helper.php';
require '/path/to/config-1.php';
require '/path/to/config-2.php';

define('INTERNAL_ACCESS', true);
require '/path/to/step-handler.php';

$logFile = '/path/to/log/delete-check.txt';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ❌ Invalid method\n", FILE_APPEND);
    exit("Method Not Allowed");
}

$client_id = $_POST['client_id'] ?? '';
$payload = $_POST['payload'] ?? '';
$auth_tag = $_POST['auth_tag'] ?? '';

$db = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$db) {
    die("DB connection failed: " . mysqli_connect_error());
}

$stmt = $db->prepare("SELECT col_modifier, col_result, col_used FROM placeholder_table WHERE col_uuid = ? LIMIT 1");
$stmt->bind_param("s", $client_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    die("❌ Invalid UUID.");
}

$row = $result->fetch_assoc();
$modifier = (int)$row['col_modifier'];
$expected = (int)$row['col_result'];

if ((int)$row['col_used'] === 1) {
    die("⚠ This challenge has already been used.");
}

$update = $db->prepare("UPDATE placeholder_table SET col_used = 1 WHERE col_uuid = ?");
$update->bind_param("s", $client_id);
$update->execute();

function deriveKey(string $id, string $secret): string {
    $rawKey = hash_hmac('sha256', $id, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$decodedPayload = base64_decode($payload);
$nonce = substr($decodedPayload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = substr($decodedPayload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$key = deriveKey($client_id, APP_SECRET);
$decrypted = sodium_crypto_secretbox_open($cipher, $nonce, $key);
if ($decrypted === false) {
    die("❌ Decryption failed.");
}

$data = json_decode($decrypted, true);
$value1 = $data['closest1'] ?? null;
$target1 = $data['target1'] ?? null;

if ($value1 === null || $target1 === null) {
    die("❌ Invalid decrypted payload.");
}

$expected_hmac = hash_hmac('sha256', "$client_id|$target1", APP_SECRET);
if (!hash_equals($expected_hmac, $auth_tag)) {
    die("❌ HMAC validation failed.");
}

$expected = $expected % $modifier;
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated_closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$value1 !== (string)$calculated_closest1) {
    die("❌ Challenge math validation failed.");
}

$keyFile  = basename($_POST['key_file'] ?? '');
$username = $_POST['username'] ?? '';
$nickname = $_POST['nickname'] ?? '';

if (!preg_match('/^login-[a-f0-9]{16}-priv\\.pem$/', $keyFile)) die("Invalid key file.");
if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) die("Invalid username.");
if (!preg_match('/^[a-zA-Z0-9]{8}$/', $nickname)) die("Invalid nickname.");

file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ✅ Finish triggered for $nickname ($keyFile)\n", FILE_APPEND);

$filePath = "/path/to/keys/$keyFile";

if (file_exists($filePath)) {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ❌ Key not downloaded. Triggering cleanup for $nickname\n", FILE_APPEND);
    shell_exec("curl -s -X POST -d 'key_file=$keyFile&username=$username&nickname=$nickname' http://localhost/reg/cleanup_all.php > /dev/null 2>&1 &");
    echo '<div style="display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f9f9f9;">
            <div style="text-align: center; padding: 2rem; border: 1px solid #ccc; border-radius: 8px; background-color: #fff; max-width: 500px; width: 90%;">
                <h3 style="color: #d9534f;">❌ Steps were not followed as expected. Registration canceled and data removed.</h3>
                <p style="color: #555;">You might’ve jumped ahead — let’s go through registration again in 5 seconds.</p>
            </div>
          </div>';
    echo '<meta http-equiv="refresh" content="5;url=index-reg.php">';
    exit;
} else {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ✅ Key was downloaded — continuing registration for $nickname\n", FILE_APPEND);
}

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
if (!$redis->auth(MMDC_REDIS_PASS)) {
    die('Redis authentication failed');
}

$redisKey = "reg:$nickname";
$redisValue = $redis->get($redisKey);

if (!$redisValue && file_exists($filePath)) {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ❌ Redis key expired for $nickname — key NOT downloaded — redirecting to index-reg.php\n", FILE_APPEND);
    header("Location: index-reg.php");
    exit;
}

if (!$redisValue && !file_exists($filePath)) {
    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ❌ Redis key expired for $nickname — key WAS downloaded — redirecting to index2-reg.php\n", FILE_APPEND);
    header("Location: index2-reg.php");
    exit;
}

$redis->del($redisKey);

list($nonceB64, $cipherB64) = explode('::', $redisValue);
$nonce = base64_decode($nonceB64);
$ciphertext = base64_decode($cipherB64);

$masterKey = hex2bin(trim(file_get_contents('/path/to/master.key')));
$json = sodium_crypto_secretbox_open($ciphertext, $nonce, $masterKey);
if ($json === false) die("❌ Data decryption failed.");

$data = json_decode($json, true);
if (!is_array($data)) die("❌ Registration data corrupted.");

$passwordHash = $data['passwordHash'] ?? '';
$pubKeyB64    = $data['publicKey'] ?? '';
$pubSigB64    = $data['publicSig'] ?? '';
$privSigB64   = $data['privateSig'] ?? '';

@unlink($filePath);

// Success UI
echo '<meta http-equiv="refresh" content="3;url=../index-login.php">';

secure_memory_cleanup($client_id);
secure_memory_cleanup($payload);
secure_memory_cleanup($auth_tag);
secure_memory_cleanup($keyFile);
secure_memory_cleanup($filePath);
secure_memory_cleanup($nickname);
secure_memory_cleanup($username);
secure_memory_cleanup($nonce);
secure_memory_cleanup($ciphertext);
secure_memory_cleanup($json);
secure_memory_cleanup($passwordHash);
secure_memory_cleanup($pubKeyB64);
secure_memory_cleanup($pubSigB64);
secure_memory_cleanup($privSigB64);
secure_memory_cleanup($expected_hmac);
secure_memory_cleanup($decodedPayload);
secure_memory_cleanup($data);

unset($stmt, $update, $redis);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Registration Complete</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .registration-box {
            padding: 2rem;
            border: 1px solid #ccc;
            border-radius: 8px;
            background-color: #f9f9f9;
            max-width: 500px;
            width: 85%;
            text-align: center;
        }
        .registration-box h2 {
            color: #4CAF50;
        }
    </style>
</head>
<body>
    <div class="registration-box">
        <h2>✅ Registration completed</h2>
        <p>You will be redirected to the login page.</p>
    </div>
</body>
</html>
