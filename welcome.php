<?php
// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");



require '/var/secure-config/config.php';  


function secure_memory_cleanup(&$data) {
    if (is_string($data)) {
        sodium_memzero($data);
    } else {
        $data = null;
    }
    unset($data);
}

define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';


$uuid = $_POST['uuid'] ?? '';
$encryptedPayload = $_POST['data'] ?? '';
$provided_hmac = $_POST['hmac'] ?? '';
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';






if (!$uuid || !$encryptedPayload || !$provided_hmac || !$username || !$password) {
    die("Missing challenge or login input.");
}


$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die(" DB connection failed: " . mysqli_connect_error());
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
    die("This challenge has already been used.");
}


$update = $RegConn->prepare("UPDATE turn_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();


function deriveKey(string $uuid, string $secret): string {
    $rawKey = hash_hmac('sha256', $uuid, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$decodedPayload = base64_decode($encryptedPayload);
$nonce = substr($decodedPayload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = substr($decodedPayload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$key = deriveKey($uuid, APP_SECRET);
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


$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 999999);

$insert = $RegConn->prepare("INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
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

list($closest1, $target1) = calculateClosestMod($new_modifier, $new_expected);


$verifyStmt = $RegConn->prepare("SELECT modifier, expected_result FROM tour_formula WHERE uuid = ?");
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


$key = deriveKey($new_uuid, APP_SECRET);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plaintext = json_encode([
    'closest1' => $closest1,
    'target1'  => $target1
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$new_uuid|$target1", APP_SECRET);



$post_uuid = $new_uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;







//step1

$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("DB connection failed: " . mysqli_connect_error());
}

}


$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

if (!$username || !$password) {
    die("Username or password missing.");
}



$nickStmt = $Pconn->prepare("SELECT KEIMXZbEmS FROM kfhEzOfm WHERE K4mZ7aQ2 = ?");
$nickStmt->bind_param("s", $username);
$nickStmt->execute();
$nickStmt->bind_result($nickname);
$nickStmt->fetch();
$nickStmt->close();
$Pconn->close();

if (!$nickname) {
    die("Nickname not found for user.");
}



$pwStmt = $Conn->prepare("SELECT IRgqaSAF FROM bDHXCdBi WHERE Jq7TmXcV = ?");
$pwStmt->bind_param("s", $nickname);
$pwStmt->execute();
$pwStmt->bind_result($passwordHash);
$pwStmt->fetch();
$pwStmt->close();
$Conn->close();

if (!$passwordHash || !password_verify($password, $passwordHash)) {
   header("Location: index-login.php?invalid password");
exit;
}


$pubStmt = $Conn->prepare("SELECT ed25519_pubkey, ed25519_signature FROM BWLytOoP WHERE xiagmWEB = ?");
$pubStmt->bind_param("s", $nickname);
$pubStmt->execute();
$pubStmt->bind_result($storedPubKeyB64, $signatureB64);
$pubStmt->fetch();
$pubStmt->close();
$Conn->close();

if (!$storedPubKeyB64 || !$signatureB64) {
    header("Location: index-login.php?publickey or signature not found");
exit;
}




$uploadedKey = $_FILES['attachment']['tmp_name'] ?? '';
if (!$uploadedKey || !file_exists($uploadedKey)) {
    header("Location: index-login.php?No private key uploaded");
exit;
}

$privateKeyPEM = file_get_contents($uploadedKey);
$cleanedKey = trim(str_replace([
    '-----BEGIN PRIVATE KEY-----',
    '-----END PRIVATE KEY-----',
    "\r", "\n"
], '', $privateKeyPEM));

$privateKey = base64_decode($cleanedKey, true);
if ($privateKey === false || strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    header("Location: index-login.php?Invalid private key format.");
    exit;
}


$derivedPublicKey = sodium_crypto_sign_publickey_from_secretkey($privateKey);
$storedPublicKey = base64_decode($storedPubKeyB64, true);

if (!$storedPublicKey || !hash_equals($derivedPublicKey, $storedPublicKey)) {
    header("Location: index-login.php?Uploaded private key does NOT match stored public key.");
    exit;
}





$signature = base64_decode($signatureB64, true);
if ($signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
    die("Failed to decode or invalid signature length.");
}


$RegConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$RegConn) die("DB connection failed");

$stmt = $Conn->prepare("SELECT Lm2DpJzE FROM bDHXCdBi WHERE gSlsWmfu = ?");
$stmt->bind_param("s", $nickname);
$stmt->execute();
$stmt->bind_result($privSigB64);
$stmt->fetch();
$stmt->close();
$Conn->close();

if (!$privSigB64) {
    header("Location: index-login.php?Private key signature not found");
exit;
}

$privSig = base64_decode($privSigB64, true);
$originalFileName = basename($_FILES['attachment']['name']);
$dataToSign = $privateKey . "|FILENAME:" . $originalFileName;

$serverPubKey = base64_decode(trim(preg_replace('/-----.*?-----|\s+/', '', file_get_contents('/var/signature/sign_pub.key'))));

if (!sodium_crypto_sign_verify_detached($privSig, $dataToSign, $serverPubKey)) {
    header("Location: index-login.php");
exit;
}





$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$conn) {
    die("DB connection failed: " . mysqli_connect_error());
}

$stmt = $conn->prepare("SELECT UxCJkwey FROM kfhEzOfm WHERE KEIMXZbEmS = ?");
$stmt->bind_param("s", $nickname);
$stmt->execute();
$result = $stmt->get_result();

$keyStatus = null;
if ($row = $result->fetch_assoc()) {
    $keyStatus = (int)$row['RfcM5R35Ap'];
}


$stmt->close();
$conn->close();



if (is_null($keyStatus) || $keyStatus % 2 !== 0) {
    echo "<html><body><div style='margin:3em auto;text-align:center;font-size:20px;'>
        You need to generate your key to send/receive secure messages, $nickname
    </div></body></html>";
} else {
    
    secure_memory_cleanup($username);
    secure_memory_cleanup($password);



    
    echo <<<HTML
<html>
    <head>
        <title>Redirecting to Inbox</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
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
}

?>






<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Navigation Menu</title>
    <style>
  body {
    font-family: Arial, sans-serif;
    background-color: #fbfcf5;
    margin: 0;
    padding: 20px;
    text-align: center;
  }

  .centered-text {
    font-size: 24px;
    color: #333;
    margin-top: 50px;
  }

  button {
    padding: 12px 20px;
    background-color: #80c683;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    cursor: pointer;
    transition: background-color 0.3s;
  }

  button:hover {
    background-color: #45a049;
  }
</style>

    
</head>
<body>


<div class="nav-bar">
    <div class="nav-wrapper">
        <ul>
            
            
                <form method="POST" action="mkulcs-gen/key-message.php">
                    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
                    <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
                    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
					<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
                    <button type="submit">Generate key</button>
                </form>
           
		</ul>

</body>
</html>

