<?php
// --- Headers to prevent caching ---
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");


require '/var/secure-config/config.php';

// === Validate HTTP method ===
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Invalid request method.");
}

// --- Enable debug output ---
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// --- Config + internal auth ---

define('INTERNAL_ACCESS', true);
require '/var/lepes/lepteto.php';

// --- Incoming POST (move this BEFORE any use) ---
$uuid = $_POST['uuid'] ?? '';
$encryptedPayload = $_POST['data'] ?? '';
$provided_hmac = $_POST['hmac'] ?? '';
$nickname = $_POST['nickname'] ?? '';



// --- Check presence ---
if (!$encryptedPayload || !$uuid || !$provided_hmac) {
    http_response_code(400);
    die("❌ Missing POST data.");
}
//eddig fixen mikodik a wwelcome.php-tol


// --- Input validation ---
if (!$uuid || !$encryptedPayload || !$provided_hmac) {
    die("Missing input data.");
}



$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("DB connection failed: " . mysqli_connect_error());
}

// --- Validate UUID entry ---
$stmt = $mysqli->prepare("SELECT modifier, expected_result, used FROM turn_formula WHERE uuid = ? LIMIT 1");
$stmt->bind_param("s", $uuid);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $stmt->close();
    $mysqli->close();
    die("Invalid UUID.");
}

$formula = $result->fetch_assoc();
$stmt->close();

if ((int)$formula['used'] === 1) {
    $mysqli->close();
    die(" Challenge already used.");
}

// --- Mark challenge as used ---
$update = $mysqli->prepare("UPDATE turn_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();
$update->close();
$mysqli->close();

// --- Decrypt and verify payload ---
function deriveKey(string $uuid, string $secret): string {
    return substr(hash_hmac('sha256', $uuid, $secret, true), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$key = deriveKey($uuid, $lepteto);

$decoded = base64_decode($encryptedPayload);
$nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$decrypted = sodium_crypto_secretbox_open($cipher, $nonce, $key);
if ($decrypted === false) {
    die("Decryption failed.");
}

$data = json_decode($decrypted, true);
$closest1 = $data['closest1'] ?? null;
$target1 = $data['target1'] ?? null;

if ($closest1 === null || $target1 === null || (int)$formula['modifier'] === 0) {
    die("Invalid payload or formula.");
}

// --- Math verification ---
$modifier = (int)$formula['modifier'];
$expected = (int)$formula['expected_result'];
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$closest1 !== (string)$calculated) {
    die("Challenge validation failed.");
}

// --- Generate new challenge ---
$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

// --- Insert new challenge ---
$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("DB reconnect failed: " . mysqli_connect_error());
}
$insert = $mysqli->prepare("
    INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used)
    VALUES (?, 'mod', ?, ?, 0)
");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();
$insert->close();
$mysqli->close();

// --- Calculate new challenge values ---
function calculateClosestMod($modifier, $expected) {
    $expected = $expected % $modifier;
    $target = random_int(50000000, 999999999);
    $delta = $target - $expected;
    $k1 = intdiv($delta, $modifier);
    $k2 = $k1 + 1;
    $x1 = $modifier * $k1 + $expected;
    $x2 = $modifier * $k2 + $expected;
    return (abs($x1 - $target) <= abs($x2 - $target)) ? [$x1, $target] : [$x2, $target];
}

list($closest1, $target1) = calculateClosestMod($new_modifier, $new_expected);

// --- Encrypt new challenge ---
$new_key = deriveKey($new_uuid, $lepteto);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$payload = json_encode(['closest1' => $closest1, 'target1' => $target1]);
$ciphertext = sodium_crypto_secretbox($payload, $nonce, $new_key);
$encryptedPayload = base64_encode($nonce . $ciphertext);

// --- HMAC for verification ---
$hmac = hash_hmac('sha256', "$new_uuid|$target1", APP_SECRET);

// --- Output values for client ---
$post_uuid = $new_uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;





// === Check user download flag ===
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$conn) {
    die("DBS DB connection failed: " . mysqli_connect_error());
}

$stmt = $conn->prepare("SELECT IhgZnH4K FROM IbGDu844K WHERE w5pxw3Tr = ?");
$stmt->bind_param("s", $nickname);
$stmt->execute();
$result = $stmt->get_result();
if ($result->num_rows === 0) {
    die("User not found.");
}
$row = $result->fetch_assoc();
$flag = (int)$row['P8Jw6P97'];
$stmt->close();
$conn->close();

if ($flag % 2 === 0) {
    die("You have already downloaded your private key.");
}

// === Generate X25519 key pair ===
$keypair = sodium_crypto_box_keypair();
$userPublicKey = sodium_crypto_box_publickey($keypair);
$userPrivateKey = sodium_crypto_box_secretkey($keypair);

// === Load Ed25519 system signing key ===
$systemSigningKeyRaw = file_get_contents('/var/signature/signature_priv.key');
$systemSigningKey = base64_decode(trim(preg_replace('/-----.*?-----|\s+/', '', $systemSigningKeyRaw)));

if ($systemSigningKey === false || strlen($systemSigningKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    die("Invalid system signing key.");
}

// === Sign public key ===
$publicSignature = sodium_crypto_sign_detached($userPublicKey, $systemSigningKey);

// === Generate random filename for private key ===
function generateKeyFilename(string $prefix = 'mess', string $suffix = 'priv'): string {
    $rand = bin2hex(random_bytes(10)); // 20-char randomness
    return "{$prefix}-{$rand}-{$suffix}.key";
}

$priv_filename = generateKeyFilename();
$privPath = "/var/www/html/mess_keys/$priv_filename";



// === Save private key (base64 encoded) ===
if (!file_put_contents($privPath, base64_encode($userPrivateKey))) {
    die("Failed to save private key.");
}
chmod($privPath, 0600);

// === Sign private key contents and filename ===
$dataToSign = $userPrivateKey . "|FILENAME:$priv_filename";
$privateSignature = sodium_crypto_sign_detached($dataToSign, $systemSigningKey);
$privateSigB64 = base64_encode($privateSignature);


// === Load master key ===
$masterKey = hex2bin(trim(file_get_contents('/var/secure/master.key')));

// === Encode values ===
$pubKeyB64 = base64_encode($userPublicKey);
$pubSigB64 = base64_encode($publicSignature);
$privSigB64 = base64_encode($privateSignature); // Assuming this is set earlier

// === Build payload ===
$data = [
    'publicKey' => $pubKeyB64,
    'publicSig' => $pubSigB64,
    'privateSig' => $privSigB64,
    'nickname' => $nickname
];

// === Encrypt payload ===
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encryptedBlob = sodium_crypto_secretbox(json_encode($data), $nonce, $masterKey);
$redisPayload = base64_encode($nonce) . '::' . base64_encode($encryptedBlob);

// === Save to Redis ===
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('412bYwqPJNcm67GY6GigXWyZAGOL8IHs4B3LX');
$redis->setex("keymsg:$nickname", 60, $redisPayload);

// === Optional: background handler
shell_exec("python3 /var/sum/manager_keymsg.py $nickname > /dev/null 2>&1 &");
?>




<!DOCTYPE html>
<html lang="en">
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
    max-width: 400px;
    width: 100%;
}
.registration-box h2 {
    text-align: center;
    margin-bottom: 1.5rem;
}
.registration-box form {
    display: flex;
    flex-direction: column;
    gap: 15px;
}
.form-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
}
.form-row label {
    min-width: 130px;
    font-weight: bold;
}
.form-row input[type="text"],
.form-row input[type="password"] {
    flex: 1;
    padding: 8px;
    max-width: 100%;
    box-sizing: border-box;
}
.registration-box input[type="submit"] {
    margin-top: 10px;
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
.form-column {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
}
</style>

  <meta charset="UTF-8">
  <title>Download Your Private Key</title>
</head>
<body>
  <div class="registration-box">
  <p>Please download your private key to send/receive secure messages</p>
  <div class="form-row">
  <form action="download_mkey.php" method="post">
    <input type="hidden" name="key_file" value="<?php echo htmlspecialchars($priv_filename); ?>">
    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
    <input type="submit" value="Step 1 Download Private key">
  </form>
  <form action="finish-mreg.php" method="post">
	<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
	<input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
     <input type="hidden" name="key_file" value="<?php echo htmlspecialchars($priv_filename); ?>">
    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
    <input type="submit" value="Step 2 Finish Process">
  </form>
  </div>
  </div>
</body>
</html>
