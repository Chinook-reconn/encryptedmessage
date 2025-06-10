<?php
// vfolyamat.php - Decrypt a message using ECC + AES-256-GCM hybrid encryption


header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");


define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';

require '/var/connect/config.php';



$post_uuid       = $_POST['uuid'] ?? '';
$post_data       = $_POST['data'] ?? '';
$post_hmac       = $_POST['hmac'] ?? '';
$post_nickname   = $_POST['nickname'] ?? '';
$post_message_id = $_POST['id'] ?? '';

if (!$post_uuid || !$post_data || !$post_hmac || !$post_nickname) {
    die(" Missing input data (UUID, Payload, HMAC, or Nickname).");
}


$RegConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$RegConn) {
    die("DB connection failed: " . mysqli_connect_error());
}

$stmt = $RegConn->prepare("SELECT modifier, expected_result, used FROM tour_formula WHERE uuid = ? LIMIT 1");
$stmt->bind_param("s", $post_uuid);
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

$update = $RegConn->prepare("UPDATE tour_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $post_uuid);
$update->execute();

function deriveKey(string $uuid, string $secret): string {
    return substr(hash_hmac('sha256', $uuid, $secret, true), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$key     = deriveKey($post_uuid, $lepteto);
$decoded = base64_decode($post_data);
$nonce   = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher  = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$decrypted = sodium_crypto_secretbox_open($cipher, $nonce, $key);
if ($decrypted === false) {
    die("Decryption failed.");
}

$data = json_decode($decrypted, true);
$closest1 = $data['closest1'] ?? null;
$target1  = $data['target1'] ?? null;

if ($closest1 === null || $target1 === null || $modifier === 0) {
    die("Invalid decrypted payload or formula.");
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

$new_uuid     = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

$insert = $RegConn->prepare("INSERT INTO tour_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();


$next_uuid = $new_uuid;
$next_modifier = $new_modifier;
$next_expected = $new_expected % $new_modifier;

$next_target = random_int(500000, 9999999999);
$delta = $next_target - $next_expected;
$k1 = intdiv($delta, $next_modifier);
$k2 = $k1 + 1;
$x1 = $next_modifier * $k1 + $next_expected;
$x2 = $next_modifier * $k2 + $next_expected;
$next_closest = (abs($x1 - $next_target) <= abs($x2 - $next_target)) ? $x1 : $x2;

$next_key = deriveKey($next_uuid, $lepteto);
$next_nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$next_plaintext = json_encode(['closest1' => $next_closest, 'target1' => $next_target]);
$next_ciphertext = sodium_crypto_secretbox($next_plaintext, $next_nonce, $next_key);
$next_data = base64_encode($next_nonce . $next_ciphertext);
$next_hmac = hash_hmac('sha256', "$next_uuid|$next_target", $lepteto);

$next_uuid = $new_uuid; 
$next_data = base64_encode($next_nonce . $next_ciphertext); 
$next_hmac = hash_hmac('sha256', "$new_uuid|$target1", $lepteto);
$next_nickname = $post_nickname; 






$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("DB connection failed: " . mysqli_connect_error());
}

$stmt = $MsgConn->prepare("
    SELECT BqT6Zp9, 4uEY1Kr, zP3TxPriv
    FROM MugGidrt
    WHERE fG9X2zQ = ?
    LIMIT 1
");
$stmt->bind_param("s", $post_nickname);
$stmt->execute();
$stmt->bind_result($x25519PubB64, $x25519SigB64, $privKeySigB64);
$stmt->fetch();
$stmt->close();
$Conn->close();

if (!$x25519PubB64 || !$x25519SigB64 || !$privKeySigB64) {
    die("Missing required key/signature data for user: " . htmlspecialchars($post_nickname));
}


$x25519Pub = base64_decode($x25519PubB64, true);
$x25519Sig = base64_decode($x25519SigB64, true);
$privKeySig = base64_decode($privKeySigB64, true);

if (!$x25519Pub || strlen($x25519Pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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
if (!$x25519Sig || strlen($x25519Sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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
if (!$privKeySig || strlen($privKeySig) !== SODIUM_CRYPTO_SIGN_BYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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






$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("Message DB connection failed: " . mysqli_connect_error());
}

$stmt = $MsgConn->prepare("
    SELECT BqT6Zp9, 4uEY1Kr, zP3TxPriv
    FROM MugGidrt
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
       echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="visszafejtes.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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
if (!$x25519Sig || strlen($x25519Sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
    die("Invalid X25519 public key signature format.");
}
if (!$privKeySig || strlen($privKeySig) !== SODIUM_CRYPTO_SIGN_BYTES) {
        echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="visszafejtes.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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


if (
    !isset($_FILES['private_key']) ||
    $_FILES['private_key']['error'] !== UPLOAD_ERR_OK
) {
        echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="visszafejtes.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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

$uploadedFile = $_FILES['private_key'];
$filename = basename($uploadedFile['name']);
$base64PrivateKey = trim(file_get_contents($uploadedFile['tmp_name']));
$rawPrivateKey = base64_decode($base64PrivateKey, true);

if (!$rawPrivateKey || strlen($rawPrivateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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

$dataToVerify = $rawPrivateKey . "|FILENAME:" . $filename;


$MsgConn = mysqli_connect(MMDC_HOST, MMDC_USER, MMDC_PASS, MMDC_DB);
if (!$MsgConn) {
    die("Message DB connection failed: " . mysqli_connect_error());
}

$stmt = $MsgConn->prepare("
    SELECT zP3TxPriv, BqT6Zp9, 4uEY1Kr
    FROM MugGidrt
    WHERE fG9X2zQ = ?
    LIMIT 1
");
$stmt->bind_param("s", $post_nickname); 
$stmt->execute();
$stmt->bind_result($privKeySigB64, $publicKeyB64, $pubKeySigB64);
$stmt->fetch();
$stmt->close();
$MsgConn->close();

if (!$privKeySigB64 || !$publicKeyB64 || !$pubKeySigB64) {
    die("No key data found for user: " . htmlspecialchars($post_nickname));
}


$ownerPrivKeySig = base64_decode($privKeySigB64, true);
$ownerPublicKey = base64_decode($publicKeyB64, true);
$ownerPubSig = base64_decode($pubKeySigB64, true);

if (
    !$ownerPrivKeySig || strlen($ownerPrivKeySig) !== SODIUM_CRYPTO_SIGN_BYTES ||
    !$ownerPublicKey || strlen($ownerPublicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES ||
    !$ownerPubSig || strlen($ownerPubSig) !== SODIUM_CRYPTO_SIGN_BYTES
) {
    die("Invalid or malformed key or signature data.");
}


$systemPubKeyRaw = file_get_contents('/var/signature/sign_pub.key');
$systemPubKey = base64_decode(trim(preg_replace('/-----.*?-----|\s+/', '', $systemPubKeyRaw)), true);

if (!$systemPubKey || strlen($systemPubKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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


if (!sodium_crypto_sign_verify_detached($ownerPrivKeySig, $dataToVerify, $systemPubKey)) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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


if (!sodium_crypto_sign_verify_detached($ownerPubSig, $ownerPublicKey, $systemPubKey)) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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


$derivedPublicKey = sodium_crypto_box_publickey_from_secretkey($rawPrivateKey);
if (!hash_equals($derivedPublicKey, $ownerPublicKey)) {
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
    </head>
    <body onload="document.forms[0].submit();">
        <form method="POST" action="inbox.php">
            <input type="hidden" name="uuid" value="{$next_uuid}">
            <input type="hidden" name="data" value="{$next_data}">
            <input type="hidden" name="hmac" value="{$next_hmac}">
            <input type="hidden" name="nickname" value="{$next_nickname}">
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



$recipient_private_key = $rawPrivateKey;



$MsgConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$MsgConn) {
    die("Could not connect to message DB: " . mysqli_connect_error());
}

$stmt = $MsgConn->prepare("SELECT sender, reci, subject, mess FROM GdVXUEwi WHERE id = ? LIMIT 1");
$stmt->bind_param("i", $post_message_id);
$stmt->execute();
$result = $stmt->get_result();
if ($result->num_rows === 0) {
    die("No message found for ID: " . htmlspecialchars($post_message_id));
}
$row = $result->fetch_assoc();
$senderNickname = $row['sender'];
$recipientNickname = $row['reci'];
$post_data = $row['mess'];

if ($post_nickname !== $recipientNickname) {
    die("You are not the recipient of this message.");
}


$update = $MsgConn->prepare("UPDATE GdVXUEwi SET status = 'opened' WHERE id = ?");
$update->bind_param("i", $post_message_id);
$update->execute();
$update->close();
$MsgConn->close();


$MsgConn = mysqli_connect(MMDC_HOST, MMDC_USER, MMDC_PASS, MMDC_DB);
$stmt = $MsgConn->prepare("SELECT BqT6Zp9, 4uEY1Kr FROM MugGidrt WHERE fG9X2zQ = ? LIMIT 1");
$stmt->bind_param("s", $senderNickname);
$stmt->execute();
$result = $stmt->get_result();
if ($result->num_rows === 0) {
    die("No public key found for sender nickname: " . htmlspecialchars($senderNickname));
}
$row = $result->fetch_assoc();
$senderPublicKey = base64_decode($row['BqT6Zp9']);
$senderSignature = base64_decode($row['4uEY1Kr']);
$stmt->close();
$MsgConn->close();


$signKeyPath = '/var/www/html/sign/sign_pub.key';
if (file_exists($signKeyPath)) {
    $publicSigningKey = base64_decode(trim(file_get_contents($signKeyPath)));
    if (!sodium_crypto_sign_verify_detached($senderSignature, $senderPublicKey, $publicSigningKey)) {
        die("Signature verification failed.");
    }
}


$shared_secret = sodium_crypto_scalarmult($recipient_private_key, $senderPublicKey);


$aes_key_path = '/var/AES/aes_key.key';
$aes_key = base64_decode(trim(file_get_contents($aes_key_path)));
if ($aes_key === false || strlen($aes_key) !== 32) {
    die("Invalid AES-256 master key.");
}


$final_key = hash_hmac('sha256', $shared_secret, $aes_key, true);


$decoded_payload = base64_decode($post_data);
$nonce_length = SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
$nonce = substr($decoded_payload, 0, $nonce_length);
$ciphertext = substr($decoded_payload, $nonce_length);

$plaintext = sodium_crypto_aead_aes256gcm_decrypt($ciphertext, '', $nonce, $final_key);
if ($plaintext === false) {
    die("Decryption failed. Message may be tampered or key mismatch.");
}


sodium_memzero($recipient_private_key);
sodium_memzero($senderPublicKey);
sodium_memzero($shared_secret);
sodium_memzero($final_key);
sodium_memzero($aes_key);
if (isset($publicSigningKey)) sodium_memzero($publicSigningKey);



?>

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


<div class="nav-bar">
  <div class="nav-wrapper">
    <ul>
      <li>
        <form method="POST" action="inbox.php">
			<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($next_uuid); ?>">
			<input type="hidden" name="data" value="<?php echo htmlspecialchars($next_data); ?>">
			<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($next_hmac); ?>">
			<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($post_nickname); ?>">
			<button type="submit">Go Inbox</button>
		</form>
      </li>
      <li>
        <form method="POST" action="outbox.php">
			<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($next_uuid); ?>">
			<input type="hidden" name="data" value="<?php echo htmlspecialchars($next_data); ?>">
			<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($next_hmac); ?>">
			<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($post_nickname); ?>">
			<button type="submit">Go outbox</button>
		</form>
        </form>
      </li>
      <li>
        <form method="POST" action="logout.php">
			<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($next_uuid); ?>">
			<input type="hidden" name="data" value="<?php echo htmlspecialchars($next_data); ?>">
			<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($next_hmac); ?>">
			<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($post_nickname); ?>">
			<button type="submit">Logout</button>
		</form>
      </li>
      
    </ul>
  </div>
</div>
<center>
<?php if (!empty($plaintext)): ?>
  <div class="encrypted-box">
    <h3>📝 Original Message (Before Encryption)</h3>
    <label for="plaintext-output">🔓 Unencrypted Plaintext Message</label>
    <pre id="plaintext-output"><?php echo htmlspecialchars($plaintext); ?></pre>
  </div>
<?php endif; ?>
</center>
</body>
</html>



