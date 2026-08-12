<?php
header('Content-Type: text/html; charset=utf-8');
echo "<h2>MAITAMA CONNECTION TEST FROM RENDER</h2>";
echo "Server IP: " . $_SERVER['SERVER_ADDR'] . "<br><br>";

// Test 1: DNS
$ip = gethostbyname("app.maitamadatahub.com");
echo "1. DNS Resolves to: " . $ip . "<br>";

// Test 2: Port 443
$start = microtime(true);
$fp = @fsockopen("app.maitamadatahub.com", 443, $errno, $errstr, 5);
$time = round((microtime(true) - $start) * 1000);
if ($fp) {
    echo "2. Port 443: OPEN ✅ in {$time}ms<br>";
    fclose($fp);
} else {
    echo "2. Port 443: BLOCKED ❌ Error: $errstr ($errno)<br>";
}

// Test 3: Real API Call
echo "<br><h3>3. Testing API Call:</h3>";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://app.maitamadatahub.com/api/topup");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer k5KGdQ5wPXHzur0Uq12xtvpe2RSglFxEmuFEy6qV',
    'Content-Type: application/json'
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, '{"amount":10,"mobile_number":"07047457735","network":1}');
curl_setopt($ch, CURLOPT_VERBOSE, true);
curl_setopt($ch, CURLOPT_STDERR, fopen('php://temp', 'w+'));

$response = curl_exec($ch);
$error = curl_error($ch);
$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "<pre>";
if($error) {
    echo "CURL ERROR: " . $error . "\n"; // This will show ETIMEDOUT
    echo "HTTP CODE: " . $httpcode;
} else {
    echo "RESPONSE: " . $response;
}
echo "</pre>";
?>