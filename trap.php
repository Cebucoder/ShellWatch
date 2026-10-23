<?php
/**
 * ShellWatch Honeypot Trap Sensor
 * Ibutang kini sa imong test server o honeypot directory.
 * Bisag kinsa nga mag-access o mag-upload diri mo-trigger dayon og webhook sa imong Globe!
 */

// Kuhaon ang IP address sa attacker/hacker
$attacker_ip = $_SERVER['REMOTE_ADDR'];

// Kung naay gipasa nga proxy headers (cloudflare/nginx reverse proxy)
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $attacker_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $attacker_ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
}

$target_domain = $_SERVER['HTTP_HOST'];
$request_uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

// Ilisdi kini sa imong tinuod nga Render Webhook URL!
$webhook_url = 'https://shellwatch.onrender.com/api/webhook/attack';

// Data nga i-padala sa imong Render backend
$data = array(
    'ip' => $attacker_ip,
    'domain' => $target_domain,
    'shellType' => 'WSO / PHP Backdoor Upload',
    'payload' => $method . ' ' . $request_uri
);

$options = array(
    'http' => array(
        'header'  => "Content-type: application/json\r\n",
        'method'  => 'POST',
        'content' => json_encode($data),
        'timeout' => 2
    )
);

$context  = stream_context_create($options);
@file_get_contents($webhook_url, false, $context);

// (Opsyonal) Pwede nimo ipakita sa hacker nga "Forbidden" o blangko nga page aron dili nila maduda nga honeypot
http_response_code(403);
echo "Access Denied.";
exit;
?>