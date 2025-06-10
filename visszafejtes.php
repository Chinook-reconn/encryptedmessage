<?php
//visszafejtes.php

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Invalid request method.");
}

// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';



// Sanitize and fetch POST values
$post_uuid = $_POST['uuid'] ?? '';
$post_data = $_POST['data'] ?? '';
$post_hmac = $_POST['hmac'] ?? '';
$post_nickname = $_POST['nickname'] ?? '';
$message_id = $_POST['id'] ?? '';
$senderNickname = $_POST['kuldo'] ?? '';
$subject = $_POST['subject'] ?? '';
$sentAt = $_POST['sent_at'] ?? '';


$uuid = trim($post_uuid);
$encryptedPayload = trim($post_data);
$provided_hmac = trim($post_hmac);
$nickname = trim($post_nickname);
$recipientNickname = $_POST['nickname'] ?? '';

if (!$uuid || !$encryptedPayload || !$provided_hmac || !$nickname) {
    echo "<strong>Debug Info:</strong><br>";
    echo "UUID: [" . htmlspecialchars($uuid) . "]<br>";
    echo "Payload: [" . htmlspecialchars($encryptedPayload) . "]<br>";
    echo "HMAC: [" . htmlspecialchars($provided_hmac) . "]<br>";
    echo "Nickname: [" . htmlspecialchars($nickname) . "]<br>";
    die("Missing input data (UUID, Payload, HMAC, or Nickname).");
}


// Connect to database
$Conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$Conn) {
    die("Registration DB connection failed: " . mysqli_connect_error());
}

// Get challenge data
$stmt = $Conn->prepare("SELECT modifier, expected_result, used FROM tour_formula WHERE uuid = ? LIMIT 1");
$stmt->bind_param("s", $uuid);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo "<strong>DEBUG:</strong> UUID not found in DB: [" . htmlspecialchars($uuid) . "]<br>";
    die("Invalid UUID.");
}

$formula = $result->fetch_assoc();
$modifier = (int)$formula['modifier'];
$expected = (int)$formula['expected_result'];

if ((int)$formula['used'] === 1) {
    die("This challenge has already been used.");
}

// Mark challenge as used
$update = $RegConn->prepare("UPDATE tour_formula SET used = 1 WHERE uuid = ?");
$update->bind_param("s", $uuid);
$update->execute();

// Decrypt
function deriveKey(string $uuid, string $secret): string {
    $rawKey = hash_hmac('sha256', $uuid, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
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

$insert = $RegConn->prepare("INSERT INTO tour_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();

$uuid = $new_uuid;
$modifier = $new_modifier;
$expected = $new_expected;

// Generate new challenge values
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
$hmac = hash_hmac('sha256', "$uuid|$target1", $lepteto);

// POST values for next step
$post_uuid = $uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;
$post_nickname = $nickname;



?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Inbox Example</title>
  <style>
  body {
  font-family: Arial, sans-serif;
  background-color: #fbfcf5;
  margin: 0;
  padding: 20px;
}

/* === NAVIGATION BAR === */
.nav-bar {
  background-color: #fbfcf5;
  width: 100%;
}

.nav-wrapper {
  width: 30%;
  margin: 0 auto;
}

ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  display: flex;
  justify-content: space-between;
  background-color: #fbfcf5;
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

/* === CENTERED TEXT === */
.centered-text {
  text-align: center;
  margin-top: 50px;
  font-size: 24px;
  color: #333;
}

/* === INBOX TABLE === */
.inbox-container {
  max-width: 70%;
  margin: 0 auto;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.inbox-header {
  background-color: #80c683;
  color: white;
  padding: 16px;
  font-size: 1.5em;
  text-align: center;
}

.inbox-table {
  width: 100%;
  border-collapse: collapse;
}

.inbox-table th, .inbox-table td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
}

.inbox-table th {
  background-color: #ddf3de;
  color: #333;
}

.inbox-table tr:hover {
  background-color: #f9f9f9;
}

.unread {
  font-weight: bold;
  background-color: #fbf4f4;
}

.opened-tag {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.8em;
  color: white;
}

.opened-yes {
  background-color: #80c683;
}

.opened-no {
  background-color: #c45e58;
}

.sender-link {
  color: #3498db;
  text-decoration: none;
}

.sender-link:hover {
  text-decoration: underline;
}

/* === ACTION BUTTONS === */
.action-buttons {
  display: flex;
  justify-content: center;
  gap: 20px;
  margin-top: 20px;
}

.action-buttons a {
  padding: 12px 20px;
  background-color: #80c683;
  color: white;
  text-decoration: none;
  border-radius: 8px;
  transition: background-color 0.3s;
}

.action-buttons a:hover {
  background-color: #45a049;
}

/* === MESSAGE VIEW / DECRYPT === */
.message-container {
  max-width: 70%;
  margin: 40px auto;
  background: #fff;
  padding: 24px;
  border-radius: 10px;
  box-shadow: 0 6px 14px rgba(0, 0, 0, 0.1);
}

h2 {
  text-align: center;
  color: #4CAF50;
  margin-bottom: 20px;
}

.info-block {
  margin-bottom: 16px;
}

.info-label {
  font-weight: bold;
  color: #333;
  margin-bottom: 4px;
}

.info-content {
  background-color: #f4f4f4;
  padding: 10px 14px;
  border-radius: 6px;
  max-height: 120px;
  overflow: auto;
  font-family: monospace;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.file-upload {
  margin: 20px 0;
}

.button {
  display: inline-block;
  padding: 12px 20px;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1em;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.button:hover {
  background-color: #45a049;
}
</style>
</head>
<body>


<div class="nav-bar">
    <div class="nav-wrapper">
        <ul>
        

            <!-- Inbox (POST) -->
            <li>
              <form method="POST" action="send-message.php">
					<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
					<input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
					<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
					<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
					<button type="submit">Send Message</button>
			</form>
            </li>
			<!-- outbox (POST) -->
			<li>
              <form method="POST" action="outbox.php">
					<input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
					<input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
					<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
					<input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
					<button type="submit">Go Outbox</button>
			</form>
            </li>
            <!-- Logout (POST) -->
            <li>
                <form method="POST" action="logout.php">
                    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
                    <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
                    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
                    <button type="submit">Logout</button>
                </form>
            </li>
        </ul>
    </div>
</div>

<div class="message-container">
  <h2>Your private looks like this mess-********************-priv.key</h2>

  <!-- Message Info -->
  <div class="info-block">
    <div class="info-label">Sender:</div>
    <p class="info-content"><?php echo htmlspecialchars($senderNickname); ?></p>
  </div>

  <div class="info-block">
    <div class="info-label">Recipient:</div>
    <p class="info-content"><?php echo htmlspecialchars($recipientNickname); ?></p>
  </div>

  <div class="info-block">
    <div class="info-label">Subject:</div>
    <p class="info-content"><?php echo htmlspecialchars($subject); ?></p>
  </div>

  <div class="info-block">
    <div class="info-label">Date Sent:</div>
    <p class="info-content"><?php echo htmlspecialchars($sentAt); ?></p>
  </div>

  <!-- Upload Private Key -->
  <form method="POST" action="vfolyamat.php" enctype="multipart/form-data">
    <div class="file-upload">
      <label for="private_key"><strong>Attach Your Private Key:</strong></label><br>
      <input type="file" name="private_key" id="private_key" required accept=".key">
    </div>

    <!-- Preserve hidden values for decryption -->
    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($uuid); ?>">
    <input type="hidden" name="data" value="<?php echo htmlspecialchars($encryptedPayload); ?>">
    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($hmac); ?>">
    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
    <input type="hidden" name="id" value="<?php echo htmlspecialchars($message_id); ?>">

    <button type="submit" class="button">Decrypt Message</button>
  </form>
</div>


</body>
</html>
