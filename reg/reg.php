<?php
// Secure memory cleanup
function secure_memory_cleanup(&$var) {
    if (is_string($var)) {
        $var = str_repeat("\0", strlen($var));
    }
    unset($var);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Invalid request method.");
}

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once '/path/to/config-1.php';


define('INTERNAL_ACCESS', true);
require '/path/to/step-handler.php';

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
    die("\u274C Error 001");
}

$row = $result->fetch_assoc();
$modifier = (int)$row['col_modifier'];
$expected = (int)$row['col_result'];

if ((int)$row['col_used'] === 1) {
    die("\u26A0 Error 002");
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
    die("\u274C Error 003");
}

$data = json_decode($decrypted, true);
$value1 = $data['closest1'] ?? null;
target1 = $data['target1'] ?? null;

if ($value1 === null || $target1 === null) {
    die("\u274C Error 004");
}

$expected_hmac = hash_hmac('sha256', "$client_id|$target1", APP_SECRET);
if (!hash_equals($expected_hmac, $auth_tag)) {
    die("\u274C Error 005");
}

$expected = $expected % $modifier;
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated_closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$value1 !== (string)$calculated_closest1) {
    die("\u274C Error 006");
}

$new_id = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 999999);

$insert = $db->prepare("INSERT INTO placeholder_table (col_uuid, col_type, col_modifier, col_result, col_used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_id, $new_modifier, $new_expected);
$insert->execute();

function calculateClosestMod($modifier, $expected) {
    $expected = $expected % $modifier;
    $target = random_int(5000000, 99999999999);
    $delta = $target - $expected;
    $k1 = intdiv($delta, $modifier);
    $k2 = $k1 + 1;
    $x1 = $modifier * $k1 + $expected;
    $x2 = $modifier * $k2 + $expected;
    $closest = (abs($x1 - $target) <= abs($x2 - $target)) ? $x1 : $x2;
    return [$closest, $target];
}

list($new_closest, $new_target) = calculateClosestMod($new_modifier, $new_expected);

$key = deriveKey($new_id, APP_SECRET);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$plaintext = json_encode([
    'closest1' => $new_closest,
    'target1' => $new_target
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$new_id|$new_target", APP_SECRET);

$post_id = $new_id;
$post_payload = $encryptedPayload;
$post_tag = $hmac;

secure_memory_cleanup($client_id);
secure_memory_cleanup($payload);
secure_memory_cleanup($auth_tag);
secure_memory_cleanup($decodedPayload);
secure_memory_cleanup($nonce);
secure_memory_cleanup($cipher);
secure_memory_cleanup($key);
secure_memory_cleanup($decrypted);
secure_memory_cleanup($data);
secure_memory_cleanup($expected_hmac);
secure_memory_cleanup($new_id);
secure_memory_cleanup($new_modifier);
secure_memory_cleanup($new_expected);
secure_memory_cleanup($new_closest);
secure_memory_cleanup($new_target);
secure_memory_cleanup($plaintext);
secure_memory_cleanup($ciphertext);
secure_memory_cleanup($post_id);
secure_memory_cleanup($post_payload);
secure_memory_cleanup($post_tag);

unset($stmt, $update, $insert, $result, $db); // Free DB resources


?>
<!DOCTYPE html>
<html>
<head>
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
    margin-bottom: 1.5rem;
}
.registration-box form {
    display: flex;
    flex-direction: column;
    gap: 15px;
}
.registration-box input[type="submit"] {
    padding: 10px;
    background-color: #4CAF50;
    color: white;
    border: none;
    cursor: pointer;
    border-radius: 4px;
}
.registration-box input[type="submit"]:hover {
    background-color: #45a049;
}
</style>
</head>
<body>
    <div class="registration-box">
        <h2>Continue Registration</h2>
        <form action="finish_registration.php" method="post">
            <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($post_id); ?>">
            <input type="hidden" name="payload" value="<?php echo htmlspecialchars($post_payload); ?>">
            <input type="hidden" name="auth_tag" value="<?php echo htmlspecialchars($post_tag); ?>">
            <input type="submit" value="Proceed to Step 2">
        </form>
    </div>
</body>
</html>
