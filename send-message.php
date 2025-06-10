<?php
//send message

// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require '/var/secure-config/config.php';


define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';

// Input data
$uuid = $_POST['uuid'] ?? '';
$encryptedPayload = $_POST['data'] ?? '';
$provided_hmac = $_POST['hmac'] ?? '';
$nickname = $_POST['nickname'] ?? '';


if (!$uuid || !$encryptedPayload || !$provided_hmac || !$nickname) {
    die("Missing input data (UUID, Payload, HMAC, or Nickname).");
}


// Connect to database
$RegConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$RegConn) {
    die("Registration DB connection failed: " . mysqli_connect_error());
}

// Get challenge data
$stmt = $RegConn->prepare("SELECT modifier, expected_result, used FROM turn_formula WHERE uuid = ? LIMIT 1");
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

// Mark challenge as used
$update = $RegConn->prepare("UPDATE turn_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();

// Decrypt
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

if ($closest1 === null || $target1 === null || $modifier === 0) {
    die("Invalid decrypted payload or formula.");
}

// Validate challenge
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$calculated_closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

if ((string)$closest1 !== (string)$calculated_closest1) {
    die("Challenge validation failed.");
}

// Generate next challenge
$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

$insert = $RegConn->prepare("INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();

$uuid = $new_uuid;
$modifier = $new_modifier;
$expected = $new_expected;

// Generate new challenge values
function calculateClosestMod($modifier, $expected) {
    $expected = $expected % $modifier;
    $target = random_int(50000000, 9999999999);
    $delta = $target - $expected;
    $k1 = intdiv($delta, $modifier);
    $k2 = $k1 + 1;

    $x1 = $modifier * $k1 + $expected;
    $x2 = $modifier * $k2 + $expected;
    $closest = (abs($x1 - $target) <= abs($x2 - $target)) ? $x1 : $x2;

    return [$closest, $target];
}

list($closest1, $target1) = calculateClosestMod($modifier, $expected);

// Encrypt new challenge
$key = deriveKey($uuid, $lepteto);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plaintext = json_encode([
    'closest1' => $closest1,
    'target1'  => $target1
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$uuid|$target1", APP_SECRET);

// POST values for next step
$post_uuid = $uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;
$post_nickname = $nickname;

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


<!-- MESSAGE FORM -->
<div class="message-container">
  <form method="POST" action="titkositas.php" enctype="multipart/form-data" class="message-form">
    <h2>People will found you on this name <?php echo $post_nickname; ?></h2>

    <!-- Required hidden challenge data -->
    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
    <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($post_nickname); ?>">

    <!-- Message fields -->
    <label for="recipient">To:</label>
    <input type="text" id="recipient" name="recipient" placeholder="Recipient name" maxlength="8" required>

    <label for="subject">Subject:</label>
    <input type="text" id="subject" name="subject" placeholder="Message subject" maxlength="50" required>

    <label for="message">Message:</label>
    <textarea id="message" name="message" placeholder="Write your message here..." maxlength="2000" required></textarea>

    <label for="private_key">Attach Private Key:</label>
    <input type="file" id="private_key" name="private_key" accept=".key" required>

    <div class="button-pair">
      <div class="button-group">
        <button type="submit" class="button">Encrypt & Send</button>
      </div>
    </div>
  </form>
</div>



</body>
</html>
