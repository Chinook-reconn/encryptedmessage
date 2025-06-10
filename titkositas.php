<?php

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");


define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';



$uuid = strip_tags(trim($_POST['uuid'] ?? ''));
$encryptedPayload = strip_tags(trim($_POST['data'] ?? ''));
$provided_hmac = strip_tags(trim($_POST['hmac'] ?? ''));
$senderNickname = strip_tags(trim($_POST['nickname'] ?? ''));
$recipientNickname = strip_tags(trim($_POST['recipient'] ?? ''));

if (!$uuid || !$encryptedPayload || !$provided_hmac || !$senderNickname) {
    die("Missing input data.");
}


$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("Registration DB connection failed: " . mysqli_connect_error());
}

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
$modifier = (int)$formula['modifier'];
$expected = (int)$formula['expected_result'];

if ((int)$formula['used'] === 1) {
    $stmt->close();
    $mysqli->close();
    die("This challenge has already been used.");
}

$stmt->close();
$update = $mysqli->prepare("UPDATE turn_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();
$update->close();
$mysqli->close();

$key = hash_hmac('sha256', $uuid, $lepteto, true);
$key = substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
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

if ($closest1 === null || $target1 === null || $modifier === 0) {
    die("Invalid decrypted payload or modifier.");
}

$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated_closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$closest1 !== (string)$calculated_closest1) {
    die("Challenge validation failed.");
}

$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("DB connection failed: " . mysqli_connect_error());
}
$insert = $mysqli->prepare("INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();
$insert->close();
$mysqli->close();

$uuid = $new_uuid;
$modifier = $new_modifier;
$expected = $new_expected % $modifier;
$target1 = random_int(50000, 9999999999);
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

$key = hash_hmac('sha256', $uuid, $lepteto, true);
$key = substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$plaintext = json_encode(['closest1' => $closest1, 'target1' => $target1]);
$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$uuid|$target1", $stepper);


$message = htmlspecialchars(strip_tags(trim($_POST['message'] ?? '')));
$subject = htmlspecialchars(strip_tags(trim($_POST['subject'] ?? '')));


if ($senderNickname === '' || $recipientNickname === '' || $message === '' || $subject === '') {
    die("All fields are required.");
}

if (!preg_match('/^[a-zA-Z0-9_]{3,100}$/', $senderNickname) || !preg_match('/^[a-zA-Z0-9_]{3,100}$/', $recipientNickname)) {
    die("Invalid nickname format.");
}

if (strlen($subject) > 51) {
    die("Subject too long (max 50 characters).");
}

if (strlen($message) > 2001) {
    die("Message too long (max 2000 characters).");
}


if ($senderNickname === '' || $recipientNickname === '' || $message === '' || $subject === '') {
    die("All fields are required.");
}

if (!preg_match('/^[a-zA-Z0-9_]{3,100}$/', $senderNickname) || !preg_match('/^[a-zA-Z0-9_]{3,100}$/', $recipientNickname)) {
    die("Invalid nickname format.");
}
if (strlen($subject) > 255) {
    die("Subject too long (max 255 characters).");
}
if (strlen($message) > 5000) {
    die("Message too long (max 5000 characters).");
}






$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("DB connection failed: " . mysqli_connect_error());
}

$stmt = $Conn->prepare("
    SELECT BqT6Zp9, vaIqLTzE, buHqgYHM
    FROM fvXcUdyzTO
    WHERE fG9X2zQ = ?
    LIMIT 1
");
$stmt->bind_param("s", $senderNickname);
$stmt->execute();
$stmt->bind_result($x25519PubB64, $x25519SigB64, $privKeySigB64);
$stmt->fetch();
$stmt->close();
$Conn->close();

if (!$x25519PubB64 || !$x25519SigB64 || !$privKeySigB64) {
    die("Missing required key/signature data for user: " . htmlspecialchars($senderNickname));
}


$x25519Pub = base64_decode($x25519PubB64, true);
$x25519Sig = base64_decode($x25519SigB64, true);
$privKeySig = base64_decode($privKeySigB64, true);

if (!$x25519Pub || strlen($x25519Pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
    die("Invalid public key format.");
}
if (!$x25519Sig || strlen($x25519Sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
    die("Invalid public key signature format.");
}
if (!$privKeySig || strlen($privKeySig) !== SODIUM_CRYPTO_SIGN_BYTES) {
    die("Invalid private key signature format.");
}




$uploadedFile = $_FILES['private_key'];
$filename = basename($uploadedFile['name']);
$base64PrivateKey = trim(file_get_contents($uploadedFile['tmp_name']));
$rawPrivateKey = base64_decode($base64PrivateKey, true);

if (!$rawPrivateKey || strlen($rawPrivateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
    die("Invalid private key format.");
}

$dataToVerify = $rawPrivateKey . "|FILENAME:" . $filename;

$MsgConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$MsgConn) {
    die("Message DB connection failed: " . mysqli_connect_error());
}


$stmt = $MsgConn->prepare("SELECT zP3TxPriv FROM fvXcUdyzTO WHERE fG9X2zQ = ? LIMIT 1");
$stmt->bind_param("s", $senderNickname);
$stmt->execute();
$stmt->bind_result($zP3TxPrivB64);
$stmt->fetch();
$stmt->close();

$signature = base64_decode($zP3TxPrivB64, true);



$stmt = $Conn->prepare("SELECT BqT6Zp9 FROM fvXcUdyzTO WHERE fG9X2zQ = ? LIMIT 1");
$stmt->bind_param("s", $recipientNickname);
$stmt->execute();
$stmt->bind_result($recipientPubB64);
$stmt->fetch();
$stmt->close();

$recipientPublicKey = base64_decode($recipientPubB64, true);
if (!$recipientPublicKey || strlen($recipientPublicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="send-message2.php">
            <input type="hidden" name="uuid" value="{$uuid}">
            <input type="hidden" name="data" value="{$encryptedPayload}">
            <input type="hidden" name="hmac" value="{$hmac}">
            <input type="hidden" name="nickname" value="{$senderNickname}">
            <input type="hidden" name="error" value="missingkey">
            <noscript>
                <p>JavaScript is disabled. Please click below to continue.</p>
                <button type="submit">Continue</button>
            </noscript>
        </form>
    </body>
</html>
HTML;
    exit;
}



$systemPubKey = base64_decode(trim(preg_replace(
    '/-----.*?-----|\s+/', '', file_get_contents('/var/signature/sign_pub.key')
)), true);

if (!sodium_crypto_sign_verify_detached($signature, $dataToVerify, $systemPubKey)) {
    die("Signature check failed: private key or filename altered.");
}
$MsgConn->close();




$senderPrivateKey = $rawPrivateKey;

$sharedSecret = sodium_crypto_scalarmult($senderPrivateKey, $recipientPublicKey);
$aesKeyPath = '/var/AES/AES_Key.key';
$aesKey = base64_decode(trim(file_get_contents($aesKeyPath)));
if ($aesKey === false || strlen($aesKey) !== 32) {
    die("Invalid AES-256 key.");
}

$finalKey = hash_hmac('sha256', $sharedSecret, $aesKey, true);
$nonce = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
$ciphertext = sodium_crypto_aead_aes256gcm_encrypt($message, '', $nonce, $finalKey);
$payload = base64_encode($nonce . $ciphertext);

$DB = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$DB) {
    die(" Could not connect to DB: " . mysqli_connect_error());
}
$expireDate = date('Y-m-d H:i:s', strtotime('+7 days'));
$encodedNonce = base64_encode($nonce);
$stmt = $DB->prepare("INSERT INTO fQEZZvjE (sender, recipi, subject, mess, nonce, expire_date) VALUES (?, ?, ?, ?, ?, ?)");
if (!$stmt) {
    die("Prepare failed: " . $DB->error);
}
$stmt->bind_param("ssssss", $senderNickname, $recipientNickname, $subject, $payload, $encodedNonce, $expireDate);
if (!$stmt->execute()) {
    echo "DB Insert Error: " . htmlspecialchars($stmt->error) . "<br>";
}
$stmt->close();
$DB->close();



if (isset($senderPrivateKey) && is_string($senderPrivateKey)) {
    sodium_memzero($senderPrivateKey);
}
if (isset($recipientPublicKey) && is_string($recipientPublicKey)) {
    sodium_memzero($recipientPublicKey);
}
if (isset($sharedSecret) && is_string($sharedSecret)) {
    sodium_memzero($sharedSecret);
}
if (isset($finalKey) && is_string($finalKey)) {
    sodium_memzero($finalKey);
}
if (isset($aesKey) && is_string($aesKey)) {
    sodium_memzero($aesKey);
}

unset(
    $privateKeyRaw, $plaintext, $ciphertext, $data,
    $row, $formula, $decoded, $decrypted, $stmt, $result,
    $DB, $MsgConn, $mysqli, $key, $nonce, $cipher, $filename,
    $base64PrivateKey, $zP3TxPrivB64, $x25519PubB64,
    $x25519SigB64, $privKeySigB64, $systemPubKey,
    $signature, $uploadedFile, $recipientPubB64
);


$post_uuid = $uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;
$nickname = $senderNickname;
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Send Message</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #fbfcf5;
      margin: 0;
      padding: 0;
      align-items: center;       /* Vertical centering */
    }

.nav-bar {
  background-color: #f4f4f4;
  width: 100%;
  margin: 0 auto; 
  background-color: #fbfcf5;
}

    .nav-wrapper {
      max-width: 35%;
      margin: 0 auto;
    }

    .nav-wrapper ul {
      list-style-type: none;
      margin: 0;
      padding: 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .nav-wrapper li {
      margin: 0;
    }

    li a,
    li form button {
      display: block;
      color: #4CAF50;
      text-align: center;
      padding: 14px 20px;
      text-decoration: none;
      transition: background-color 0.3s;
      background: none;
      border: none;
      font: inherit;
      cursor: pointer;
    }

    li a:hover,
    li form button:hover {
      background-color: #80c683;
      color: white;
      border-radius: 8px;
    }

    li form {
      margin: 0;
      padding: 0;
    }

    .message-container {
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 40px 20px;
    }

    .message-form {
      background-color: #fff;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 6px 14px rgba(0, 0, 0, 0.1);
      width: 100%;
      max-width: 700px;
    }

    .message-form h2 {
      text-align: center;
      color: #4CAF50;
      margin-bottom: 20px;
    }

    .message-form label {
      display: block;
      margin-bottom: 6px;
      font-weight: bold;
      color: #333;
      margin-top: 12px;
    }

    .message-form input[type="text"],
    .message-form textarea,
    .message-form input[type="file"] {
      width: 95%;
      margin: 0 0 16px 0;
      display: block;
      padding: 10px 12px;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-family: inherit;
      font-size: 1em;
      background-color: #f9f9f9;
    }

    .message-form textarea {
      height: 150px;
      resize: vertical;
    }

    .button-pair {
      display: flex;
      justify-content: center;
      gap: 10px;
      margin-top: 20px;
    }

    .button-group {
      flex: 1;
      max-width: 300px;
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    .button {
      width: 100%;
      padding: 12px;
      background-color: #4CAF50;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 1em;
      font-family: inherit;
      cursor: pointer;
      transition: background-color 0.3s ease;
    }

    .button:hover {
      background-color: #45a049;
    }

    @media (max-width: 768px) {
      .nav-wrapper ul {
        flex-direction: column;
        align-items: center;
      }

      .button-pair {
        flex-direction: column;
      }

      .message-form input[type="text"],
      .message-form textarea,
      .message-form input[type="file"] {
        width: 90%;
      }
    }
    
    
    
    
 .encrypted-box {
  background-color: #fbfcf5;
  margin: 40px auto;
  padding: 20px 24px;
  border-radius: 10px;
  max-width: 70%;
  box-shadow: 0 6px 14px rgba(0, 0, 0, 0);
  border: 1px solid transparent; /* Transparent border added here */
}

.encrypted-box h3 {
  color: #4CAF50;
  font-size: 20px;
  margin-bottom: 10px;
}

.encrypted-box label {
  font-weight: bold;
  color: #333;
  display: block;
  margin-bottom: 8px;
}

.encrypted-box pre {
  width: 95%;
  padding: 12px;
  font-family: monospace;
  background-color: #fbfcf5;
  border: 1px solid rgba(204, 204, 204, 0);
  border-radius: 6px;
  font-size: 0.95em;
  resize: vertical;
  white-space: pre-wrap; /* Handle long lines gracefully */
  word-break: break-word;
}

    
    
  </style>
</head>
<body>

<!-- NAVIGATION BAR -->
<div class="nav-bar">
  <div class="nav-wrapper">
    <ul>
      <li>
        <form method="POST" action="inbox.php">
          <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
          <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
          <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
          <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
          <button type="submit">Go Inbox</button>
        </form>
      </li>
      <li>
        <form method="POST" action="outbox.php">
          <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
          <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
          <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
          <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
          <button type="submit">Go Outbox</button>
        </form>
      </li>
      <li>
        <form method="POST" action="logout.php">
          <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
          <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
          <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
          <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
          <button type="submit">Log out</button>
        </form>
      </li>
      
    </ul>
  </div>
</div>
<center>
<?php if (!empty($payload)): ?>
 <div class="encrypted-box">
    <h3>✅ Message Encrypted Successfully</h3>
    <label for="encrypted-output">🔐 ECC + AES-256-GCM: Secure Hybrid Encryption System </label>
    <pre id="encrypted-output"><?php echo htmlspecialchars($payload); ?></pre>
</div>

<?php endif; ?>
</center>
</body>
</html>
