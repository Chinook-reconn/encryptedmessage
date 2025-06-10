<?php
//inbox.php


// Optional: prevent browser cache
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");


require '/var/secur/config.php';

define('INTERNAL_ACCESS', true);
require '/var/lepes/lepteto.php';


$uuid = $_POST['uuid'] ?? '';
$encryptedPayload = $_POST['data'] ?? '';
$provided_hmac = $_POST['hmac'] ?? '';
$nickname = $_POST['nickname'] ?? '';


if (!$uuid || !$encryptedPayload || !$provided_hmac || !$nickname) {
    die("Missing input data (UUID, Payload, HMAC, or Nickname).");
}

// Use Registration DB for rotation formula

$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("DB connection failed: " . mysqli_connect_error());
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

// Decrypt and verify
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

// Generate next challenge
$new_uuid = bin2hex(random_bytes(16));
$new_modifier = rand(150000, 300000);
$new_expected = rand(1000, 9999);

// Save the new challenge in DB
$mysqli = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$mysqli) {
    die("DB connection failed: " . mysqli_connect_error());
}
$insert = $mysqli->prepare("INSERT INTO turn_formula (uuid, formula_type, modifier, expected_result, used) VALUES (?, 'mod', ?, ?, 0)");
$insert->bind_param("sii", $new_uuid, $new_modifier, $new_expected);
$insert->execute();
$insert->close();
$mysqli->close();

// Overwrite values to use the new challenge
$uuid = $new_uuid;
$modifier = $new_modifier;
$expected = $new_expected;

// Build the new challenge payload
$expected = $expected % $modifier;
$target1 = random_int(500000, 9999999999);
$delta = $target1 - $expected;
$k1 = intdiv($delta, $modifier);
$k2 = $k1 + 1;
$x1 = $modifier * $k1 + $expected;
$x2 = $modifier * $k2 + $expected;
$closest1 = (abs($x1 - $target1) <= abs($x2 - $target1)) ? $x1 : $x2;

// Encrypt the new challenge
$key = hash_hmac('sha256', $uuid, $lepteto, true);
$key = substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$plaintext = json_encode([
    'closest1' => $closest1,
    'target1' => $target1
]);
$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);
$hmac = hash_hmac('sha256', "$uuid|$target1", $lepteto);

// These are the correct values to send to the next page:
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

    /* === PAGE ELEMENTS === */
    .centered-text {
      text-align: center;
      margin-top: 50px;
      font-size: 24px;
      color: #333;
    }

    /* === INBOX STYLES === */
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


  <?php
require '/var/secur/config.php';

$MsgConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$MsgConn) {
    die("DB connection failed: " . mysqli_connect_error());
}

// Protect against SQL injection
$nickname_safe = mysqli_real_escape_string($MsgConn, $nickname);

// Fetch messages for the recipient
$sql = "SELECT sender, subject, sent_at, status FROM WjqlIMAN WHERE reci = '$nickname_safe' ORDER BY sent_at DESC";
$result = mysqli_query($MsgConn, $sql);
?>

<?php
require '/var/Secur/config.php';

$MsgConn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$MsgConn) {
    die("DB connection failed: " . mysqli_connect_error());
}

$nickname_safe = mysqli_real_escape_string($MsgConn, $nickname);

$sql = "SELECT id, sender, subject, sent_at, status FROM WjqlIMAN WHERE reci = '$nickname_safe' ORDER BY sent_at DESC";
$result = mysqli_query($MsgConn, $sql);
?>

<div class="inbox-container">
    <div class="inbox-header">
        Inbox <br> Your name in the system: <?php echo htmlspecialchars($nickname); ?>
    </div>
    <table class="inbox-table">
        <thead>
            <tr>
                <th>Sender</th>
                <th>Subject</th>
                <th>Time</th>
                <th>Status</th>
                <th>Delete</th>
            </tr>
        </thead>
        <tbody>
<?php if (mysqli_num_rows($result) > 0): ?>
    <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <tr class="<?php echo ($row['status'] === 'sent') ? 'unread' : ''; ?>">
            <td><?php echo htmlspecialchars($row['sender']); ?></td>

            <td>
    <form method="post" action="visszafejtes.php" style="display:inline;">
    <input type="hidden" name="id" value="<?php echo htmlspecialchars($row['id']); ?>">
    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
    <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">

    <!-- Additional values -->
    <input type="hidden" name="sender" value="<?php echo htmlspecialchars($row['sender']); ?>">
    <input type="hidden" name="subject" value="<?php echo htmlspecialchars($row['subject']); ?>">
    <input type="hidden" name="sent_at" value="<?php echo htmlspecialchars($row['sent_at']); ?>">

        <?php
            $fullSubject = $row['subject'];
            $displaySubject = $fullSubject;

            $subbPos = strpos($fullSubject, 'subb');
            if ($subbPos !== false) {
                $after = substr($fullSubject, $subbPos + 4);
                if (ctype_digit($after)) {
                    $displaySubject = substr($fullSubject, 0, $subbPos);
                }
            }

            $displaySubject = trim($displaySubject);
        ?>

        <button type="submit" style="background:none;border:none;padding:0;color:#007BFF;cursor:pointer;text-decoration:underline;font:inherit;">
            <?php echo htmlspecialchars($displaySubject); ?>
        </button>
    </form>
</td>



            <td><?php echo htmlspecialchars($row['sent_at']); ?></td>

            <td>
                <span class="opened-tag <?php echo ($row['status'] === 'sent') ? 'opened-no' : 'opened-yes'; ?>">
                    <?php echo ($row['status'] === 'sent') ? 'No' : 'Yes'; ?>
                </span>
            </td>

            <td>
                <form method="post" action="torles/delete.php" style="display:inline;">
                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($row['id']); ?>">
                    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($post_uuid); ?>">
                    <input type="hidden" name="data" value="<?php echo htmlspecialchars($post_data); ?>">
                    <input type="hidden" name="hmac" value="<?php echo htmlspecialchars($post_hmac); ?>">
                    <input type="hidden" name="nickname" value="<?php echo htmlspecialchars($nickname); ?>">
                    <button type="submit" style="background:none;border:none;padding:0;color:red;cursor:pointer;text-decoration:underline;font:inherit;">
                        Delete
                    </button>
                </form>
            </td>
        </tr>
    <?php endwhile; ?>
<?php else: ?>
    <tr><td colspan="5">No messages found.</td></tr>
<?php endif; ?>
</tbody>


</body>
</html>

