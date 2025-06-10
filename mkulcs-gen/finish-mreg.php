<?php

//finish-mreg.php
// === Disable caching ===
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// === Load configs and secrets ===
require '/var/secure-config/config.php';


define('INTERNAL_ACCESS', true);
require '/var/stepper/lstep.php';


// Escape for output in HTML attributes
$uuid = $_POST['uuid'] ?? '';
$encryptedPayload = $_POST['data'] ?? '';
$provided_hmac = $_POST['hmac'] ?? '';
$nickname = $_POST['nickname'] ?? '';



// Check for missing or empty values
if (
    empty($uuid) ||
    empty($encryptedPayload) ||
    empty($provided_hmac) ||
    empty($nickname)
) {
    die("one or more post wariabl is empty.");
}




// --- Step 2: Connect to rotation DB (DB) and check UUID ---
$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("Registration DB connection failed: " . mysqli_connect_error());
}

$stmt = $Conn->prepare("SELECT modifier, expected_result, used FROM turn_formula WHERE uuid = ? LIMIT 1");
$stmt->bind_param("s", $uuid);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    die("Invalid UUID.");
}



$formula = $result->fetch_assoc();
$modifier = (int)$formula['modifier'];
$expected = (int)$formula['expected_result'];

if ((int)$formula['used'] === 1) {
    die("⚠ This challenge has already been used.");
}

// Mark UUID as used
$update = $RegConn->prepare("UPDATE turn_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();

// --- Step 3: Decrypt payload and verify HMAC ---
function deriveKey(string $uuid, string $secret): string {
    $rawKey = hash_hmac('sha256', $uuid, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$decodedPayload = base64_decode($encryptedPayload);
$nonce = substr($decodedPayload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = substr($decodedPayload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$key = deriveKey($uuid, $lepteto);
$decrypted = sodium_crypto_secretbox_open($cipher, $nonce, $key);
if ($decrypted === false) {
    die("Decryption failed.");
}

$data = json_decode($decrypted, true);
$closest1 = $data['closest1'] ?? null;
$target1 = $data['target1'] ?? null;

if ($closest1 === null || $target1 === null) {
    die("Invalid decrypted payload.");
}

$expected_hmac = hash_hmac('sha256', "$uuid|$target1", APP_SECRET);
if (!hash_equals($expected_hmac, $provided_hmac)) {
    die("HMAC validation failed.");
}

// --- Step 4: Verify challenge math ---
$expected = $expected % $modifier;
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated_closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$closest1 !== (string)$calculated_closest1) {
    die("Challenge math validation failed.");
}

// --- Step 5: Generate and insert new challenge ---
$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000000, 999999999);

$insert = $RegConn->prepare("INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();

// --- Step 6: Calculate next challenge ---
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

list($closest1, $target1) = calculateClosestMod($new_modifier, $new_expected);

// --- Step 7: Re-verify math matches inserted UUID ---
$verifyStmt = $RegConn->prepare("SELECT modifier, expected_result FROM turn_formula WHERE uuid = ?");
$verifyStmt->bind_param("s", $new_uuid);
$verifyStmt->execute();
$newFormula = $verifyStmt->get_result()->fetch_assoc();
$verifyStmt->close();

if (!$newFormula) {
    die("New UUID formula verification failed.");
}

$checkMod = (int)$newFormula['modifier'];
$checkExp = (int)$newFormula['expected_result'] % $checkMod;
$delta = $target1 - $checkExp;
$k1 = intdiv($delta, $checkMod);
$k2 = $k1 + 1;
$x1 = $checkMod * $k1 + $checkExp;
$x2 = $checkMod * $k2 + $checkExp;
$verifyClosest = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$verifyClosest !== (string)$closest1) {
    die("Math mismatch in newly inserted UUID.");
}

// --- Step 8: Encrypt new challenge ---
$key = deriveKey($new_uuid, APP_SECRET);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plaintext = json_encode([
    'closest1' => $closest1,
    'target1'  => $target1
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$new_uuid|$target1", APP_SECRET);


// --- Step 9: Prepare output variables ---
$post_uuid = $new_uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;




















// load data from RAM
// === Load Redis ===
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('Ac1vQkcnRqNiqHvuR6CAo2G1XQ6Lv1QLun'); //it is an example not a real password

// === Load master key ===
$masterKey = hex2bin(trim(file_get_contents('/var/52ZJ9jbtuG6/master.key')));

// === Load keymsg memory payload ===
$redisKeyMsg = "keymsg:$nickname";
$redisValueMsg = $redis->get($redisKeyMsg);
if (!$redisValueMsg) die("Key-message data expired or missing.");
$redis->del($redisKeyMsg); // Clean up after retrieval

list($nonceMsgB64, $cipherMsgB64) = explode('::', $redisValueMsg);
$nonceMsg = base64_decode($nonceMsgB64);
$ciphertextMsg = base64_decode($cipherMsgB64);

$jsonMsg = sodium_crypto_secretbox_open($ciphertextMsg, $nonceMsg, $masterKey);
if ($jsonMsg === false) die("Key-message decryption failed.");

$keymsgData = json_decode($jsonMsg, true);
if (!is_array($keymsgData)) die("Key-message payload corrupted.");

// === Extract fields from memory ===
$pubKeyB64     = $keymsgData['publicKey']  ?? '';
$pubSigB64     = $keymsgData['publicSig']  ?? '';
$privateSigB64 = $keymsgData['privateSig'] ?? '';

// === Validate extracted fields ===
if (empty($pubKeyB64) || empty($pubSigB64) || empty($privateSigB64)) {
    die("One or more key fields missing.");
}

// === Update MuX7dp43S (DB DB) ===
$connKey = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$connKey) {
    die("DB DB connection failed: " . mysqli_connect_error());
}

$stmt = $connKey->prepare("
    UPDATE MuX7dp43S 
    SET BqT6Zp9 = ?, 4uEY1Kr = ?, zP3TxPriv = ? 
    WHERE fG9X2zQ = ?
");
$stmt->bind_param("ssss", $pubKeyB64, $pubSigB64, $privateSigB64, $nickname);

if (!$stmt->execute()) {
    die("Update failed: " . $stmt->error);
}

if ($stmt->affected_rows === 0) {
    echo "<p>⚠No update made — nickname not found or already updated.</p>";
} else {
    echo "<p>Key data updated successfully in MuX7dp43S.</p>";
}

$stmt->close();
$connKey->close();

// === Connect to Message DB ===

$Pconn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Pconn) {
    die("dP993 DB connection failed: " . mysqli_connect_error());
}

// === Fetch current odd flag ===
$query = "SELECT 7IaXn7rC1T2 FROM Rw89jD3r3w9 WHERE G81IHw78U = ?";
$stmt = $G7fPconn->prepare($query);
$stmt->bind_param("s", $nickname);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $stmt->close();
    $MsgConn->close();
    die("Nickname not found in DB.");
}

$row = $result->fetch_assoc();
$currentFlag = (int)$row['aFTzk90p5'];

// === Generate next even number ===
$evenFlag = ($currentFlag % 2 == 0) ? $currentFlag : $currentFlag + 1;

// === Update the flag ===
$updateQuery = "UPDATE Rw89jD3r3w9 SET 7IaXn7rC1T2 = ? WHERE G81IHw78U = ?";
$updateStmt = $G7fPconn->prepare($updateQuery);
$updateStmt->bind_param("is", $evenFlag, $nickname);

if (!$updateStmt->execute()) {
    $updateStmt->close();
    $MsgConn->close();
    die("Failed to update flag: " . $updateStmt->error);
}

$updateStmt->close();
$G7fPconn->close();




// Auto-submitting POST form
echo <<<HTML
<html>
    <head>
        <title>Redirecting to Inbox</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="../inbox.php">
            <input type="hidden" name="uuid" value="{$post_uuid}">
            <input type="hidden" name="data" value="{$post_data}">
            <input type="hidden" name="hmac" value="{$post_hmac}">
            <input type="hidden" name="nickname" value="{$nickname}">
            <noscript>
                <p>JavaScript is disabled. Click the button below to proceed.</p>
                <button type="submit">Continue</button>
            </noscript>
        </form>
    </body>
</html>
HTML;
exit;



?>


