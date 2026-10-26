
<?php
/**
 * ShellWatch defensive event reporter.
 * Call this only for a relevant, detected security event.
 */

function shellwatch_report_event($event_type, $request_details = '') {
    if (!function_exists('curl_init')) {
        error_log('ShellWatch: PHP cURL extension is unavailable.');
        return false;
    }

    $webhook_url = 'https://shellwatch.onrender.com/api/webhook/attack';

    // Configure these as environment variables on your server.
    $secret = getenv('WEBHOOK_SECRET');

    if (!$secret) {
        error_log('ShellWatch: WEBHOOK_SECRET is missing.');
        return false;
    }

    // Do not trust forwarded-IP headers unless your reverse proxy
    // is explicitly configured and verified as trusted.
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        error_log('ShellWatch: Invalid client IP.');
        return false;
    }

    $domain = $_SERVER['HTTP_HOST'] ?? 'Unknown';

    // Avoid sending arbitrary request bodies, cookies or credentials.
    $data = [
        'ip'       => $ip,
        'domain'   => $domain,
        'shellType' => substr($event_type, 0, 100),
        'payload'  => substr($request_details, 0, 500),
    ];

    $ch = curl_init($webhook_url);

    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($data),
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'X-ShellWatch-Secret: ' . $secret,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT        => 4,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        error_log('ShellWatch webhook failed: ' . curl_error($ch));
    }

    curl_close($ch);

    if ($response === false || $status < 200 || $status >= 300) {
        error_log('ShellWatch webhook returned HTTP ' . $status);
        return false;
    }

    return true;
}

// Example: call this only after your security scanner
// has identified a relevant event.
// shellwatch_report_event('Suspicious PHP upload', 'Security event ID: 123');
