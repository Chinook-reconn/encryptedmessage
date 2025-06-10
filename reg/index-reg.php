<?php
// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

//echo php error
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// index-reg.php - Secure registration entry page

require '/path/to/config.php'; 


define('INTERNAL_ACCESS', true);
require '/path/to/step-handler.php';

// Generate next challenge
$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

// Connect to database
$db = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$db) {
    die("Error 001: " . mysqli_connect_error());
}

$stmt = $db->prepare("INSERT INTO placeholder_table (col_uuid, col_type, col_modifier, col_result, col_used) VALUES (?, 'mod', ?, ?, 0)");
$stmt->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$stmt->execute();

$uuid = $new_uuid;
$modifier = $new_modifier;
$expected = $new_expected;

function calculateClosestMod($modifier, $expected) {
    $expected = $expected % $modifier;
    $target = random_int(500000, 9999999999);
    $delta = $target - $expected;
    $k1 = intdiv($delta, $modifier);
    $k2 = $k1 + 1;

    $x1 = $modifier * $k1 + $expected;
    $x2 = $modifier * $k2 + $expected;
    $closest = (abs($x1 - $target) <= abs($x2 - $target)) ? $x1 : $x2;

    return [$closest, $target];
}

list($value1, $target1) = calculateClosestMod($modifier, $expected);

function deriveKey(string $uuid, string $secret): string {
    $rawKey = hash_hmac('sha256', $uuid, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$key = deriveKey($uuid, APP_SECRET);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plaintext = json_encode([
    'value1'  => $value1,
    'target1' => $target1
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$uuid|$target1", $step_handler_secret);

// Generalized POST variables
$client_uuid = $uuid;
$client_payload = $encryptedPayload;
$client_hmac = $hmac;
?>


<html>
<head>
<style>
body {
    margin: 0;
    padding: 2rem;
    background-color: #fbfcf5;
    font-family: Arial, sans-serif;
}

.page-wrapper {
    display: flex;
    flex-direction: column;
    align-items: center;
}


.info-message {
    max-width: 60%;
    padding: 1rem;
    margin-bottom: 1.5rem;
    text-align: center;
    background-color: #fff3cd;
    border: 1px solid #ffeeba;
    border-radius: 8px;
    color: #856404;
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

.registration-box label {
    font-weight: bold;
}

.registration-box input[type="text"],
.registration-box input[type="password"] {
    padding: 8px;
    box-sizing: border-box;
    width: 100%;
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

.registration-box .centered-text {
    text-align: center;
    margin-top: 1.5rem;
}

a {
    color: #4CAF50;
    text-decoration: none;
}
</style>
</head>
<body>
  <div class="page-wrapper">
    <div class="info-message">
      <p><strong>⚠️ Please follow these instructions to register successfully:</strong></p>
      <ul style="text-align: left;">
        <li>Use a strong password (min. 10 characters, with uppercase, lowercase, number, and symbol)</li>
        <li>Make sure both passwords match</li>
        <li><strong>Step 1:</strong> Download your private key</li>
        <li><strong>Step 2:</strong> Complete the registration within 1 minute</li>
      </ul>
      <p style="margin-top: 1em;">Missed a step? No worries — we’ll just send you back to try again.</p>
    </div>
	
    <div class="registration-box">
        <h2>Registration</h2>
        <form action="reg.php" method="post">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required
           maxlength="32" pattern="[a-zA-Z0-9_-]{3,32}" title="3–32 characters: letters, numbers, underscores, hyphens">

    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required
           maxlength="64" pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{10,}"
           title="Min 10 chars, with uppercase, lowercase, digit, and special character">

    <label for="confirm_password">Confirm Password:</label>
    <input type="password" name="confirm_password" id="confirm_password" required
           maxlength="64">

    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($client_uuid); ?>">
    <input type="hidden" name="data" value="<?php echo htmlspecialchars($client_payload); ?>">
    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($client_hmac); ?>">

    <input type="submit" value="Register">
</form>
<h2 class="centered-text"><a href="../index.html">Back</a></h2>
    </div>
</body>
</html>

