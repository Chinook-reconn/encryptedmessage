<?php
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");


require '/var/secure-config/config.php'; 
      

define('INTERNAL_ACCESS', true);
require '/var/step/stepper.php';


function generateUUID(): string {
    return bin2hex(random_bytes(16));
}

$uuid = generateUUID();


$modifier = rand(150000, 9999999999);
$expected = rand(1000, 99999999);


function calculateClosestMod($modifier, $expected) {
    $expected = $expected % $modifier;
    $target = random_int(500000, 999999999999);
    $delta = $target - $expected;
    $k1 = intdiv($delta, $modifier);
    $k2 = $k1 + 1;

    $x1 = $modifier * $k1 + $expected;
    $x2 = $modifier * $k2 + $expected;

    $closest = (abs($x1 - $target) <= abs($x2 - $target)) ? $x1 : $x2;
    return [$closest, $target];
}

list($closest, $target) = calculateClosestMod($modifier, $expected);


$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_DB);
if (!$conn) {
    die("DB connection failed: " . mysqli_connect_error());
}


$stmt = $conn->prepare("
    INSERT INTO tour_formula (uuid, formula_type, modifier, expected_result, used)
    VALUES (?, 'mod', ?, ?, 0)
");
$stmt->bind_param("sii", $uuid, $modifier, $expected);
if (!$stmt->execute()) {
    die("Insert failed: " . $stmt->error);
}
$stmt->close();
$conn->close();


function deriveKey(string $uuid, string $secret): string {
    $rawKey = hash_hmac('sha256', $uuid, $secret, true);
    return substr($rawKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
}

$key = deriveKey($uuid, $lepteto);
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plaintext = json_encode([
    'closest1' => $closest,
    'target1'  => $target
]);

$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
$encryptedPayload = base64_encode($nonce . $ciphertext);


$hmac = hash_hmac('sha256', "$uuid|$target", APP_SECRET);


$post_uuid = $uuid;
$post_data = $encryptedPayload;
$post_hmac = $hmac;
?>



<html>
<head>
<style>
body {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
    background-color: #fbfcf5;
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

a {
      color: #4CAF50;
      text-decoration: none;
    }
</style>
</head>
<body>
<div class="registration-box">
    <h2>User Login</h2>
    <form action="welcome.php" method="POST" enctype="multipart/form-data">
    <!-- User login fields -->
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required>

    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required>

    <div class="form-row form-column">
        <label for="attachment">Attach your private key:</label>
        <input type="file" id="attachment" name="attachment" accept=".pem" required>
    </div>

    <!-- Hidden fields for rotation formula challenge -->
    <input type="hidden" name="uuid" value="<?php echo htmlspecialchars($uuid); ?>">
<input type="hidden" name="data" value="<?php echo htmlspecialchars($encryptedPayload); ?>">
<input type="hidden" name="hmac" value="<?php echo htmlspecialchars($hmac); ?>">


        <input type="submit" value="Login">
    </form>
    <h2 class="centered-text"><a href="index.html">Back</a></h2>
</div>
</body>
</html>

