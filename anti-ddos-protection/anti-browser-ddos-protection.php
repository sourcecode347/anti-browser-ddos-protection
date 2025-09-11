<?php
/*
Plugin Name: Anti Browser DDoS Protection
Description: Rate limiting with admin panel, bot exclusions, bot IP ranges management with duplicate removal, high traffic bot logging, static asset exclusion, blocked IP logging with User Agent, IP banning with User Agent, Cloudflare real IP support, blocked bots by User Agent, auto-refresh logs every 30 seconds, automatic log expiration, and export/import for bot lists.
Version: 2.21
Author: SourceCode347
License: GPL v2 or later
Text Domain: anti-browser-ddos-protection
*/

if (!defined('ABSPATH')) {
    exit;
}

// Cloudflare IP ranges (IPv4 and IPv6)
function abdp_is_cloudflare_ip($ip) {
    $cloudflare_ranges = array(
        // IPv4 ranges
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/12',
        '172.64.0.0/13',
        '131.0.72.0/22',
        // IPv6 ranges
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    );

    foreach ($cloudflare_ranges as $range) {
        if (strpos($range, ':') !== false) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && strpos($ip, substr($range, 0, strpos($range, '::'))) === 0) {
                return true;
            }
        } else {
            list($subnet, $bits) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            if ($ip_long && $subnet_long && ($ip_long & $mask) == ($subnet_long & $mask)) {
                return true;
            }
        }
    }
    return false;
}

// Get real client IP (Cloudflare support)
function abdp_get_real_ip() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    if (abdp_is_cloudflare_ip($ip)) {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $first_ip = trim($forwarded_ips[0]);
            if (filter_var($first_ip, FILTER_VALIDATE_IP)) {
                return $first_ip;
            }
        }
    }
    return $ip;
}

// Check if User Agent is a blocked bot
function abdp_is_blocked_bot($user_agent) {
    if (empty($user_agent)) {
        return false;
    }

    $blocked_bots = get_option('abdp_blocked_bots', '');
    if (empty($blocked_bots)) {
        return false;
    }

    $bot_list = array_filter(array_map('trim', explode("\n", $blocked_bots)));
    foreach ($bot_list as $bot) {
        if (!empty($bot) && stripos($user_agent, $bot) !== false) {
            return true;
        }
    }
    return false;
}

// Check if IP belongs to known bot IP ranges
function abdp_is_suspicious_bot($ip, $user_agent) {
    $excluded_bots = get_option('abdp_excluded_bots', '');
    if (empty($excluded_bots) || empty($user_agent)) {
        return false;
    }

    $bot_list = array_filter(array_map('trim', explode("\n", $excluded_bots)));
    $is_bot = false;
    foreach ($bot_list as $bot) {
        if (!empty($bot) && stripos($user_agent, $bot) !== false) {
            $is_bot = true;
            break;
        }
    }

    if (!$is_bot) {
        return false;
    }

    // Get bot IP ranges from admin panel settings
    $bot_ip_ranges = get_option('abdp_bot_ip_ranges', '');
    if (empty($bot_ip_ranges)) {
        return true; // If no IP ranges are defined, treat all bot-like user agents as suspicious
    }

    $known_bot_ranges = array_filter(array_map('trim', explode("\n", $bot_ip_ranges)));

    foreach ($known_bot_ranges as $range) {
        list($subnet, $bits) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        if ($ip_long && $subnet_long && ($ip_long & $mask) == ($subnet_long & $mask)) {
            return false; // IP belongs to a known bot range, not suspicious
        }
    }

    // If user agent claims to be a bot but IP is not in known ranges, flag as suspicious
    return true;
}

// Register admin menu
add_action('admin_menu', 'abdp_admin_menu');
function abdp_admin_menu() {
    add_options_page(
        esc_html__('Anti Browser DDoS Protection Settings', 'anti-browser-ddos-protection'),
        esc_html__('Anti DDoS', 'anti-browser-ddos-protection'),
        'manage_options',
        'abdp-settings',
        'abdp_settings_page'
    );
}
setcookie("abdp_admin_notice", "0", time() + (86400 * 30), "/", $_SERVER['SERVER_NAME']);
// Admin notice to confirm menu registration
add_action('admin_notices', 'abdp_admin_notice');
function abdp_admin_notice() {
    if (!current_user_can('manage_options')) {
        return;
    }
    if(!isset($_COOKIE['abdp_admin_notice'])){
        printf(
            '<div class="notice notice-info is-dismissible"><p>%s <a href="%s">%s</a> %s</p></div>',
            esc_html__('Anti Browser DDoS Protection: Go to ', 'anti-browser-ddos-protection'),
            esc_url(admin_url('options-general.php?page=abdp-settings')),
            esc_html__('Settings > Anti DDoS', 'anti-browser-ddos-protection'),
            esc_html__('to configure the plugin.', 'anti-browser-ddos-protection')
        );
    }
}

// Clean up expired logs
function abdp_cleanup_expired_logs() {
    $log_expires_days = get_option('abdp_log_expires_days', 5);
    $expiration_time = time() - ($log_expires_days * DAY_IN_SECONDS);

    // Clean Blocked IPs
    $blocked_ips = get_option('abdp_blocked_ips', array());
    $blocked_ips = array_filter($blocked_ips, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time;
    });
    update_option('abdp_blocked_ips', array_values($blocked_ips));

    // Clean Banned IPs
    $banned_ips = get_option('abdp_banned_ips', array());
    $banned_ips = array_filter($banned_ips, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time;
    });
    update_option('abdp_banned_ips', array_values($banned_ips));

    // Clean High Traffic Bots
    $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
    $high_traffic_bots = array_filter($high_traffic_bots, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time;
    });
    update_option('abdp_high_traffic_bots', array_values($high_traffic_bots));
}

// Schedule log cleanup
add_action('abdp_cleanup_logs_event', 'abdp_cleanup_expired_logs');
function abdp_schedule_log_cleanup() {
    if (!wp_next_scheduled('abdp_cleanup_logs_event')) {
        wp_schedule_event(time(), 'hourly', 'abdp_cleanup_logs_event');
    }
}

// Start the scheduler on plugin activation
register_activation_hook(__FILE__, 'abdp_schedule_log_cleanup');

// AJAX handler for refreshing nonce
add_action('wp_ajax_abdp_refresh_nonce', 'abdp_refresh_nonce');
function abdp_refresh_nonce() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized', 403);
    }
    wp_send_json_success(wp_create_nonce('wp_rest'));
}

// Enqueue Chart.js on the settings page
add_action('admin_enqueue_scripts', 'abdp_enqueue_scripts');
function abdp_enqueue_scripts($hook) {
    if ($hook !== 'settings_page_abdp-settings') {
        return;
    }
    wp_enqueue_script('chart-js', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js', array(), null, true);
}

// Export handlers
add_action('admin_post_abdp_export_excluded_bots', 'abdp_export_excluded_bots');
function abdp_export_excluded_bots() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_GET['nonce'] ?? '', 'abdp_export_excluded_bots')) {
        wp_die('Unauthorized');
    }
    $data = get_option('abdp_excluded_bots', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="excluded_bots.txt"');
    echo esc_html($data);
    exit;
}

add_action('admin_post_abdp_export_bot_ip_ranges', 'abdp_export_bot_ip_ranges');
function abdp_export_bot_ip_ranges() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_GET['nonce'] ?? '', 'abdp_export_bot_ip_ranges')) {
        wp_die('Unauthorized');
    }
    $data = get_option('abdp_bot_ip_ranges', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="bot_ip_ranges.txt"');
    echo esc_html($data);
    exit;
}

add_action('admin_post_abdp_export_blocked_bots', 'abdp_export_blocked_bots');
function abdp_export_blocked_bots() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_GET['nonce'] ?? '', 'abdp_export_blocked_bots')) {
        wp_die('Unauthorized');
    }
    $data = get_option('abdp_blocked_bots', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="blocked_bots.txt"');
    echo esc_html($data);
    exit;
}

// Admin settings page
function abdp_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    // Save settings
    if (isset($_POST['abdp_save_settings'])) {
        check_admin_referer('abdp_save_settings');

        // Handle imports and append to POST values
        // Excluded Bots Import
        if (!empty($_FILES['abdp_excluded_bots_file']['name'])) {
            $file_content = file_get_contents($_FILES['abdp_excluded_bots_file']['tmp_name']);
            $new_lines = array_filter(array_map('trim', explode("\n", $file_content)));
            $current_lines = array_filter(array_map('trim', explode("\n", $_POST['abdp_excluded_bots'])));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_excluded_bots'] = implode("\n", $all_lines);
        }

        // Bot IP Ranges Import
        if (!empty($_FILES['abdp_bot_ip_ranges_file']['name'])) {
            $file_content = file_get_contents($_FILES['abdp_bot_ip_ranges_file']['tmp_name']);
            $new_lines = array_filter(array_map('trim', explode("\n", $file_content)));
            $current_lines = array_filter(array_map('trim', explode("\n", $_POST['abdp_bot_ip_ranges'])));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_bot_ip_ranges'] = implode("\n", $all_lines);
        }

        // Blocked Bots Import
        if (!empty($_FILES['abdp_blocked_bots_file']['name'])) {
            $file_content = file_get_contents($_FILES['abdp_blocked_bots_file']['tmp_name']);
            $new_lines = array_filter(array_map('trim', explode("\n", $file_content)));
            $current_lines = array_filter(array_map('trim', explode("\n", $_POST['abdp_blocked_bots'])));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_blocked_bots'] = implode("\n", $all_lines);
        }

        // Remove duplicate IP ranges
        $raw_bot_ip_ranges = sanitize_textarea_field($_POST['abdp_bot_ip_ranges']);
        $bot_ip_ranges_array = array_filter(array_map('trim', explode("\n", $raw_bot_ip_ranges)));
        $unique_bot_ip_ranges = array_unique($bot_ip_ranges_array);
        $cleaned_bot_ip_ranges = implode("\n", $unique_bot_ip_ranges);

        // Save settings
        update_option('abdp_max_requests', absint($_POST['abdp_max_requests']));
        update_option('abdp_time_window', absint($_POST['abdp_time_window']));
        update_option('abdp_excluded_bots', sanitize_textarea_field($_POST['abdp_excluded_bots']));
        update_option('abdp_blocked_bots', sanitize_textarea_field($_POST['abdp_blocked_bots']));
        update_option('abdp_bot_ip_ranges', $cleaned_bot_ip_ranges);
        update_option('abdp_ban_threshold', absint($_POST['abdp_ban_threshold']));
        update_option('abdp_ban_duration', absint($_POST['abdp_ban_duration']));
        update_option('abdp_bot_max_requests', absint($_POST['abdp_bot_max_requests']));
        update_option('abdp_log_expires_days', absint($_POST['abdp_log_expires_days']));
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Anti Browser DDoS Protection: Settings saved successfully! Duplicate IP ranges have been removed.', 'anti-browser-ddos-protection') . '</p></div>';
    }

    // Clear blocked IPs log
    if (isset($_POST['abdp_clear_blocked_log'])) {
        check_admin_referer('abdp_clear_blocked_log');
        delete_option('abdp_blocked_ips');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Anti Browser DDoS Protection: Blocked IPs log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    // Clear banned IPs log
    if (isset($_POST['abdp_clear_banned_log'])) {
        check_admin_referer('abdp_clear_banned_log');
        delete_option('abdp_banned_ips');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Anti Browser DDoS Protection: Banned IPs log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    // Clear high traffic bots log
    if (isset($_POST['abdp_clear_high_traffic_bots_log'])) {
        check_admin_referer('abdp_clear_high_traffic_bots_log');
        delete_option('abdp_high_traffic_bots');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Anti Browser DDoS Protection: High Traffic Bots log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    $max_requests = get_option('abdp_max_requests', 10);
    $time_window = get_option('abdp_time_window', 60);
    $ban_threshold = get_option('abdp_ban_threshold', 30);
    $ban_duration = get_option('abdp_ban_duration', 24);
    $bot_max_requests = get_option('abdp_bot_max_requests', 100);
    $log_expires_days = get_option('abdp_log_expires_days', 5);
    $excluded_bots = get_option('abdp_excluded_bots', "Googlebot\nBingbot\nSlurp\nDuckDuckBot\nTwitterbot\nMediapartners-Google\nGoogle-Display-Ads-Bot\nAdsBot\nfacebookexternalhit\nAdsBot-Google\nAppEngine-Google\nFeedfetcher-Google\nYandex\nAhrefsBot\nmsnbot\nbingbot\nStripebot");
    $blocked_bots = get_option('abdp_blocked_bots', "MJ12bot\nSemrushBot\nDotBot");
    $bot_ip_ranges = get_option('abdp_bot_ip_ranges', implode("\n", array(
        // Googlebot and related Google bots
        '66.249.64.0/19',
        '66.249.80.0/20',
        '66.249.92.0/23',
        '66.249.94.0/23',
        '66.249.93.0/24',
        '64.233.160.0/19',
        '64.233.161.0/24',
        '64.233.162.0/24',
        '64.233.163.0/24',
        '64.233.166.0/24',
        '64.233.167.0/24',
        '64.233.168.0/24',
        '64.233.169.0/24',
        '64.233.170.0/24',
        '64.233.171.0/24',
        '64.233.172.0/24',
        '64.233.173.0/24',
        '64.233.174.0/24',
        '64.233.175.0/24',
        '64.233.176.0/24',
        '64.233.177.0/24',
        '64.233.178.0/24',
        '64.233.179.0/24',
        '64.233.180.0/24',
        '64.233.181.0/24',
        '64.233.182.0/24',
        '64.233.183.0/24',
        '64.233.184.0/24',
        '64.233.185.0/24',
        '64.233.186.0/24',
        '64.233.187.0/24',
        '64.233.188.0/24',
        '64.233.189.0/24',
        '64.233.190.0/24',
        '64.233.191.0/24',
        '72.14.192.0/18',
        '72.14.203.0/24',
        '72.14.204.0/24',
        '72.14.205.0/24',
        '72.14.206.0/24',
        '72.14.207.0/24',
        '74.125.0.0/16',
        '108.177.8.0/21',
        '108.177.96.0/19',
        '172.217.0.0/19',
        '172.217.32.0/20',
        '172.217.128.0/19',
        '172.217.160.0/20',
        '172.217.169.0/24',
        '172.217.170.0/24',
        '172.217.171.0/24',
        '172.217.172.0/24',
        '172.217.173.0/24',
        '172.217.174.0/24',
        '172.217.175.0/24',
        '172.217.176.0/20',
        '172.217.192.0/19',
        '172.253.0.0/16',
        '173.194.0.0/16',
        '209.85.128.0/17',
        '216.58.192.0/19',
        '216.58.224.0/20',
        '216.239.32.0/19',
        '216.239.34.0/24',
        '216.239.36.0/24',
        '216.239.38.0/24',
        // Bingbot, msnbot, bingbot (Microsoft Bing)
        '157.55.0.0/16',
        '157.56.0.0/14',
        '204.79.180.0/24',
        '204.79.181.0/24',
        '204.79.182.0/24',
        '204.79.183.0/24',
        '204.79.184.0/24',
        '204.79.185.0/24',
        '204.79.186.0/24',
        '204.79.187.0/24',
        '40.77.0.0/16',
        '52.114.0.0/15',
        '64.4.0.0/18',
        '65.52.0.0/14',
        '94.245.0.0/17',
        '111.221.16.0/22',
        '111.221.29.0/24',
        '131.253.0.0/16',
        '131.253.21.0/24',
        '131.253.22.0/24',
        '131.253.23.0/24',
        '131.253.33.0/24',
        '131.253.34.0/24',
        '131.253.35.0/24',
        '131.253.37.0/24',
        '131.253.39.0/24',
        '157.54.0.0/15',
        '157.60.0.0/16',
        '168.61.0.0/16',
        '191.234.0.0/17',
        '199.47.87.0/24',
        '207.46.0.0/16',
        // Yahoo! Slurp
        '67.195.37.0/24',
        '67.195.52.0/24',
        '67.195.53.0/24',
        '67.195.54.0/24',
        '67.195.55.0/24',
        '69.147.64.0/18',
        '69.147.80.0/20',
        '69.164.208.0/20',
        '69.164.224.0/19',
        '72.30.0.0/16',
        '74.6.17.0/24',
        '74.6.18.0/23',
        '74.6.20.0/24',
        '98.136.0.0/16',
        '98.137.0.0/16',
        '98.138.0.0/16',
        '202.160.176.0/22',
        // DuckDuckBot
        '23.21.150.121/32',
        '40.88.24.0/24',
        '43.249.72.0/22',
        '50.16.0.0/16',
        '50.19.0.0/16',
        '52.70.160.0/20',
        '54.166.128.0/17',
        '54.236.0.0/15',
        '54.242.0.0/14',
        '107.22.0.0/15',
        '107.23.0.0/16',
        '149.20.64.0/18',
        '162.216.0.0/18',
        '185.185.186.0/24',
        // Twitterbot (X.com, now under xAI but IPs from AWS)
        '199.16.156.0/22',
        '199.59.148.0/22',
        '104.244.42.0/24',
        '104.244.75.0/24',
        '104.244.76.0/24',
        '104.244.78.0/24',
        '104.244.79.0/24',
        '31.13.24.0/24',
        '31.13.25.0/24',
        '31.13.26.0/24',
        '31.13.27.0/24',
        '31.13.28.0/24',
        '31.13.29.0/24',
        '31.13.30.0/24',
        '31.13.31.0/24',
        '31.13.32.0/24',
        '31.13.33.0/24',
        '31.13.34.0/24',
        '31.13.35.0/24',
        '31.13.36.0/24',
        '31.13.37.0/24',
        '31.13.38.0/24',
        '31.13.39.0/24',
        '31.13.40.0/24',
        '31.13.41.0/24',
        '31.13.42.0/24',
        '31.13.43.0/24',
        '31.13.44.0/24',
        '31.13.45.0/24',
        '31.13.46.0/24',
        '31.13.47.0/24',
        '31.13.48.0/24',
        '31.13.49.0/24',
        '31.13.50.0/24',
        '31.13.51.0/24',
        '31.13.52.0/24',
        '31.13.53.0/24',
        '31.13.54.0/24',
        '31.13.55.0/24',
        '31.13.56.0/24',
        '31.13.57.0/24',
        '31.13.58.0/24',
        '31.13.59.0/24',
        '31.13.60.0/24',
        '31.13.61.0/24',
        '31.13.62.0/24',
        '31.13.63.0/24',
        '31.13.64.0/24',
        '31.13.65.0/24',
        '31.13.66.0/24',
        '31.13.67.0/24',
        '31.13.68.0/24',
        '31.13.69.0/24',
        '31.13.70.0/24',
        '31.13.71.0/24',
        '31.13.72.0/24',
        '31.13.73.0/24',
        '31.13.74.0/24',
        '31.13.75.0/24',
        '31.13.76.0/24',
        '31.13.77.0/24',
        '31.13.78.0/24',
        '31.13.79.0/24',
        '31.13.80.0/24',
        '31.13.81.0/24',
        '31.13.82.0/24',
        '31.13.83.0/24',
        '31.13.84.0/24',
        '31.13.85.0/24',
        '31.13.86.0/24',
        '31.13.87.0/24',
        '31.13.88.0/24',
        '31.13.89.0/24',
        '31.13.90.0/24',
        '31.13.91.0/24',
        '31.13.92.0/24',
        '31.13.93.0/24',
        '31.13.94.0/24',
        '31.13.95.0/24',
        '31.13.96.0/24',
        '31.13.97.0/24',
        '31.13.98.0/24',
        '31.13.99.0/24',
        '31.13.100.0/24',
        '31.13.101.0/24',
        '31.13.102.0/24',
        '31.13.103.0/24',
        '31.13.104.0/24',
        '31.13.105.0/24',
        '31.13.106.0/24',
        '31.13.107.0/24',
        '31.13.108.0/24',
        '31.13.109.0/24',
        '31.13.110.0/24',
        '31.13.111.0/24',
        '31.13.112.0/24',
        '31.13.113.0/24',
        '31.13.114.0/24',
        '31.13.115.0/24',
        '31.13.116.0/24',
        '31.13.117.0/24',
        '31.13.118.0/24',
        '31.13.119.0/24',
        '31.13.120.0/24',
        '31.13.121.0/24',
        '31.13.122.0/24',
        '31.13.123.0/24',
        '31.13.124.0/24',
        '31.13.125.0/24',
        '31.13.126.0/24',
        '31.13.127.0/24',
        // Facebook External Hit (Meta)
        '31.13.24.0/21',
        '31.13.64.0/18',
        '69.63.176.0/20',
        '69.171.224.0/20',
        '74.119.0.0/16',
        '102.132.96.0/20',
        '129.134.0.0/16',
        '157.240.0.0/16',
        '173.252.64.0/18',
        '185.60.216.0/22',
        '185.89.216.0/22',
        // Yandex Bot
        '5.45.192.0/22',
        '5.45.196.0/23',
        '5.45.198.0/23',
        '5.45.200.0/21',
        '5.255.192.0/20',
        '77.88.0.0/20',
        '77.88.16.0/21',
        '87.250.224.0/20',
        '87.250.240.0/21',
        '93.158.128.0/20',
        '93.158.144.0/20',
        '93.158.160.0/20',
        '109.70.128.0/18',
        '141.8.128.0/20',
        '141.8.144.0/20',
        '141.8.160.0/20',
        '141.8.176.0/20',
        '178.154.192.0/20',
        '178.154.208.0/20',
        '178.154.224.0/20',
        '178.154.240.0/20',
        '213.180.192.0/20',
        '213.180.208.0/20',
        // AhrefsBot
        '151.101.1.164/32',
        '151.101.65.164/32',
        '151.101.129.164/32',
        '151.101.193.164/32',
        '151.101.2.164/32',
        '151.101.66.164/32',
        '151.101.130.164/32',
        '151.101.194.164/32',
        '151.101.3.164/32',
        '151.101.67.164/32',
        '151.101.131.164/32',
        '151.101.195.164/32',
        '151.101.0.164/32',
        '151.101.64.164/32',
        '151.101.128.164/32',
        '151.101.192.164/32',
        // Stripebot (Stripe IPs - limited known ranges, Stripe uses dynamic IPs)
        '3.18.36.0/24',
        '3.19.0.0/16',
        '18.188.0.0/15',
        '52.94.0.0/18',
        '54.218.0.0/16',
    )));
    $blocked_ips = get_option('abdp_blocked_ips', array());
    $banned_ips = get_option('abdp_banned_ips', array());
    $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
    ?>
    <style>
        .abdp-donate-link {
            position: fixed;
            top:35px;
            right:10px;
            margin-bottom: 20px;
            text-align: right;
            font-size: 16px;
            font-weight: bold;
        }
        .abdp-donate-link a {
            color: #0073aa;
            text-decoration: none;
        }
        .abdp-donate-link a:hover {
            text-decoration: underline;
        }
        .abdp-logo .abdp-logo-img {
            border-radius: 50%;
            width: 180px;
            height: 180px;
            object-fit: cover;
            position:fixed;
            right:10px;
            top:65px;
        }
        .abdp-charts-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-around;
            margin-bottom: 20px;
        }
        .abdp-chart-wrapper {
            width: 30%;
            min-width: 300px;
            margin-bottom: 20px;
        }
    </style>
    <div class="wrap">
        <div class="abdp-donate-link">
            <?php printf(
                esc_html__('Support this project with one %s', 'anti-browser-ddos-protection'),
                '<a href="https://buy.stripe.com/bIY5o70SSfam8Qo7ss" target="_blank">' . esc_html__('Donate', 'anti-browser-ddos-protection') . '</a>'
            ); ?>
        </div>
        <div class="abdp-logo">
            <?php
            $logo_url = plugin_dir_url(__FILE__) . 'Anti-Browser-DDoS-Protection.png';
            printf(
                '<img src="%s" alt="%s" class="abdp-logo-img"/>',
                esc_url($logo_url),
                esc_attr__('Anti Browser DDoS Protection Logo', 'anti-browser-ddos-protection')
            );
            ?>
        </div>
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        
        <h2><?php echo esc_html__('Rate Limiting Settings', 'anti-browser-ddos-protection'); ?></h2>
        <form method="post" action="" enctype="multipart/form-data">
            <?php wp_nonce_field('abdp_save_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="abdp_max_requests"><?php echo esc_html__('Maximum Requests (Regular Users)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_max_requests" name="abdp_max_requests" value="<?php echo esc_attr($max_requests); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Maximum number of requests allowed per IP for regular users and suspicious bots.', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_time_window"><?php echo esc_html__('Time Window (seconds)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_time_window" name="abdp_time_window" value="<?php echo esc_attr($time_window); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Time window for request counting for regular users and suspicious bots (in seconds).', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_bot_max_requests"><?php echo esc_html__('Maximum Requests (Excluded Bots)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_bot_max_requests" name="abdp_bot_max_requests" value="<?php echo esc_attr($bot_max_requests); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Maximum number of requests allowed per minute for verified excluded bots. Bots exceeding this limit are logged as High Traffic Bots.', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_ban_threshold"><?php echo esc_html__('Blocks Before Ban', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_ban_threshold" name="abdp_ban_threshold" value="<?php echo esc_attr($ban_threshold); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Number of blocks before an IP is banned.', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_ban_duration"><?php echo esc_html__('Ban Duration (hours)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_ban_duration" name="abdp_ban_duration" value="<?php echo esc_attr($ban_duration); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Duration of the ban in hours.', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_log_expires_days"><?php echo esc_html__('Log Expires (Days)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <input type="number" id="abdp_log_expires_days" name="abdp_log_expires_days" value="<?php echo esc_attr($log_expires_days); ?>" min="1" class="regular-text" required>
                        <p class="description"><?php echo esc_html__('Number of days after which logs (Blocked IPs, Banned IPs, High Traffic Bots) are automatically deleted.', 'anti-browser-ddos-protection'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_excluded_bots"><?php echo esc_html__('Excluded Bots (User Agents)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <textarea id="abdp_excluded_bots" name="abdp_excluded_bots" rows="5" cols="50" class="large-text code"><?php echo esc_textarea($excluded_bots); ?></textarea>
                        <p class="description"><?php echo esc_html__('One user agent per line. These bots will be excluded from rate limiting if their IP is verified. Example: Googlebot', 'anti-browser-ddos-protection'); ?></p>
                        <p><a href="<?php echo esc_url(admin_url('admin-post.php?action=abdp_export_excluded_bots&nonce=' . wp_create_nonce('abdp_export_excluded_bots'))); ?>"><?php echo esc_html__('Export to TXT', 'anti-browser-ddos-protection'); ?></a></p>
                        <p><?php echo esc_html__('Import from TXT (append to existing):', 'anti-browser-ddos-protection'); ?> <input type="file" name="abdp_excluded_bots_file" accept=".txt"></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_bot_ip_ranges"><?php echo esc_html__('Bot IP Ranges', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <textarea id="abdp_bot_ip_ranges" name="abdp_bot_ip_ranges" rows="10" cols="50" class="large-text code"><?php echo esc_textarea($bot_ip_ranges); ?></textarea>
                        <p class="description"><?php echo esc_html__('One IP range per line in CIDR format (e.g., 66.249.64.0/19). Verified IP Ranges for Excluded Bots.', 'anti-browser-ddos-protection'); ?></p>
                        <p><a href="<?php echo esc_url(admin_url('admin-post.php?action=abdp_export_bot_ip_ranges&nonce=' . wp_create_nonce('abdp_export_bot_ip_ranges'))); ?>"><?php echo esc_html__('Export to TXT', 'anti-browser-ddos-protection'); ?></a></p>
                        <p><?php echo esc_html__('Import from TXT (append to existing):', 'anti-browser-ddos-protection'); ?> <input type="file" name="abdp_bot_ip_ranges_file" accept=".txt"></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="abdp_blocked_bots"><?php echo esc_html__('Blocked Bots (User Agents)', 'anti-browser-ddos-protection'); ?></label></th>
                    <td>
                        <textarea id="abdp_blocked_bots" name="abdp_blocked_bots" rows="5" cols="50" class="large-text code"><?php echo esc_textarea($blocked_bots); ?></textarea>
                        <p class="description"><?php echo esc_html__('One user agent per line. These bots will be blocked immediately. Example: MJ12bot', 'anti-browser-ddos-protection'); ?></p>
                        <p><a href="<?php echo esc_url(admin_url('admin-post.php?action=abdp_export_blocked_bots&nonce=' . wp_create_nonce('abdp_export_blocked_bots'))); ?>"><?php echo esc_html__('Export to TXT', 'anti-browser-ddos-protection'); ?></a></p>
                        <p><?php echo esc_html__('Import from TXT (append to existing):', 'anti-browser-ddos-protection'); ?> <input type="file" name="abdp_blocked_bots_file" accept=".txt"></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(esc_html__('Save Settings', 'anti-browser-ddos-protection'), 'primary', 'abdp_save_settings'); ?>
        </form>

        <h2><?php echo esc_html__('Daily Statistics Charts', 'anti-browser-ddos-protection'); ?></h2>
        <div class="abdp-charts-container">
            <div class="abdp-chart-wrapper">
                <canvas id="blocked-ips-chart"></canvas>
            </div>
            <div class="abdp-chart-wrapper">
                <canvas id="banned-ips-chart"></canvas>
            </div>
            <div class="abdp-chart-wrapper">
                <canvas id="high-traffic-bots-chart"></canvas>
            </div>
        </div>

        <h2><?php echo esc_html__('Blocked IPs Log', 'anti-browser-ddos-protection'); ?></h2>
        <?php if (!empty($blocked_ips)) : ?>
            <table id="abdp-blocked-ips-table" class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('IP Address', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('User Agent', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('Timestamp', 'anti-browser-ddos-protection'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($blocked_ips as $entry) : ?>
                        <tr>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($entry['user_agent']); ?></td>
                            <td><?php echo esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" action="">
                <?php wp_nonce_field('abdp_clear_blocked_log'); ?>
                <?php submit_button(esc_html__('Clear Blocked IPs Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_blocked_log'); ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('Anti Browser DDoS Protection: No blocked IPs recorded yet.', 'anti-browser-ddos-protection'); ?></p>
        <?php endif; ?>

        <h2><?php echo esc_html__('Banned IPs Log', 'anti-browser-ddos-protection'); ?></h2>
        <?php if (!empty($banned_ips)) : ?>
            <table id="abdp-banned-ips-table" class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('IP Address', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('User Agent', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('Timestamp', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('Expires', 'anti-browser-ddos-protection'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($banned_ips as $entry) : ?>
                        <tr>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($entry['user_agent']); ?></td>
                            <td><?php echo esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])); ?></td>
                            <td><?php echo esc_html(wp_date('Y-m-d H:i:s', $entry['expires'])); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" action="">
                <?php wp_nonce_field('abdp_clear_banned_log'); ?>
                <?php submit_button(esc_html__('Clear Banned IPs Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_banned_log'); ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('Anti Browser DDoS Protection: No banned IPs recorded yet.', 'anti-browser-ddos-protection'); ?></p>
        <?php endif; ?>

        <h2><?php echo esc_html__('High Traffic Excluded Bots Log', 'anti-browser-ddos-protection'); ?></h2>
        <?php if (!empty($high_traffic_bots)) : ?>
            <table id="abdp-high-traffic-bots-table" class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('IP Address', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('User Agent', 'anti-browser-ddos-protection'); ?></th>
                        <th><?php echo esc_html__('Timestamp', 'anti-browser-ddos-protection'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($high_traffic_bots as $entry) : ?>
                        <tr>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($entry['user_agent']); ?></td>
                            <td><?php echo esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" action="">
                <?php wp_nonce_field('abdp_clear_high_traffic_bots_log'); ?>
                <?php submit_button(esc_html__('Clear High Traffic Bots Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_high_traffic_bots_log'); ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('Anti Browser DDoS Protection: No high traffic bots recorded yet.', 'anti-browser-ddos-protection'); ?></p>
        <?php endif; ?>

        <script>
            (function() {
                const apiBase = '<?php echo esc_url_raw(rest_url('abdp/v1')); ?>';
                let nonce = '<?php echo esc_js(wp_create_nonce('wp_rest')); ?>';

                let blockedChart, bannedChart, highTrafficChart;

                function fetchNonce() {
                    return fetch('<?php echo esc_url_raw(admin_url('admin-ajax.php')); ?>?action=abdp_refresh_nonce', {
                        headers: { 'X-WP-Nonce': nonce }
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Failed to refresh nonce: ' + response.statusText);
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.success) {
                            nonce = data.data;
                            return nonce;
                        } else {
                            throw new Error('Nonce refresh failed');
                        }
                    });
                }

                function processData(data) {
                    let counts = {};
                    data.forEach(entry => {
                        let date = entry.timestamp.split(' ')[0];
                        counts[date] = (counts[date] || 0) + 1;
                    });
                    let sortedDates = Object.keys(counts).sort();
                    let labels = sortedDates;
                    let values = sortedDates.map(d => counts[d]);
                    return { labels, values };
                }

                function drawChart(ctx, labels, values, title, existingChart) {
                    if (existingChart) {
                        existingChart.destroy();
                    }
                    return new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: title,
                                data: values,
                                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                borderColor: 'rgba(75, 192, 192, 1)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Count'
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Date'
                                    }
                                }
                            },
                            plugins: {
                                legend: {
                                    display: true
                                }
                            }
                        }
                    });
                }

                function fetchLogs(endpoint, tableId, chartId, title) {
                    fetch(apiBase + endpoint, {
                        headers: { 'X-WP-Nonce': nonce }
                    })
                    .then(response => {
                        if (response.status === 403) {
                            return fetchNonce().then(() => {
                                return fetch(apiBase + endpoint, {
                                    headers: { 'X-WP-Nonce': nonce }
                                });
                            });
                        }
                        return response;
                    })
                    .then(response => response.json())
                    .then(data => {
                        const tbody = document.querySelector(`#${tableId} tbody`);
                        if (!tbody) return;
                        tbody.innerHTML = ''; // Clear existing rows
                        if (data.length === 0) {
                            tbody.innerHTML = '<tr><td colspan="' + (endpoint === '/banned-ips' ? 4 : 3) + '"><?php echo esc_html__('No entries recorded yet.', 'anti-browser-ddos-protection'); ?></td></tr>';
                        } else {
                            data.forEach(entry => {
                                const row = document.createElement('tr');
                                row.innerHTML = `
                                    <td>${entry.ip}</td>
                                    <td>${entry.user_agent}</td>
                                    <td>${entry.timestamp}</td>
                                    ${endpoint === '/banned-ips' ? `<td>${entry.expires}</td>` : ''}
                                `;
                                tbody.appendChild(row);
                            });
                        }

                        // Draw chart
                        const ctx = document.getElementById(chartId).getContext('2d');
                        const { labels, values } = processData(data);
                        if (chartId === 'blocked-ips-chart') {
                            blockedChart = drawChart(ctx, labels, values, title, blockedChart);
                        } else if (chartId === 'banned-ips-chart') {
                            bannedChart = drawChart(ctx, labels, values, title, bannedChart);
                        } else if (chartId === 'high-traffic-bots-chart') {
                            highTrafficChart = drawChart(ctx, labels, values, title, highTrafficChart);
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching logs:', error);
                    });
                }

                function refreshLogs() {
                    fetchLogs('/blocked-ips', 'abdp-blocked-ips-table', 'blocked-ips-chart', 'Blocked IPs per Day');
                    fetchLogs('/banned-ips', 'abdp-banned-ips-table', 'banned-ips-chart', 'Banned IPs per Day');
                    fetchLogs('/high-traffic-bots', 'abdp-high-traffic-bots-table', 'high-traffic-bots-chart', 'High Traffic Bots per Day');
                }

                // Initial fetch
                refreshLogs();

                // Refresh every 30 seconds
                setInterval(refreshLogs, 30000);
            })();
        </script>
    </div>
    <?php
}

// Register REST API endpoints for logs
add_action('rest_api_init', 'abdp_register_rest_endpoints');
function abdp_register_rest_endpoints() {
    // Endpoint for Blocked IPs
    register_rest_route('abdp/v1', '/blocked-ips', array(
        'methods' => 'GET',
        'callback' => 'abdp_get_blocked_ips',
        'permission_callback' => function() {
            return current_user_can('manage_options');
        },
    ));

    // Endpoint for Banned IPs
    register_rest_route('abdp/v1', '/banned-ips', array(
        'methods' => 'GET',
        'callback' => 'abdp_get_banned_ips',
        'permission_callback' => function() {
            return current_user_can('manage_options');
        },
    ));

    // Endpoint for High Traffic Bots
    register_rest_route('abdp/v1', '/high-traffic-bots', array(
        'methods' => 'GET',
        'callback' => 'abdp_get_high_traffic_bots',
        'permission_callback' => function() {
            return current_user_can('manage_options');
        },
    ));
}

function abdp_get_blocked_ips($request) {
    $blocked_ips = get_option('abdp_blocked_ips', array());
    $formatted = array_map(function($entry) {
        return array(
            'ip' => esc_html($entry['ip']),
            'user_agent' => esc_html($entry['user_agent']),
            'timestamp' => esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])),
        );
    }, $blocked_ips);
    return rest_ensure_response($formatted);
}

function abdp_get_banned_ips($request) {
    $banned_ips = get_option('abdp_banned_ips', array());
    $formatted = array_map(function($entry) {
        return array(
            'ip' => esc_html($entry['ip']),
            'user_agent' => esc_html($entry['user_agent']),
            'timestamp' => esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])),
            'expires' => esc_html(wp_date('Y-m-d H:i:s', $entry['expires'])),
        );
    }, $banned_ips);
    return rest_ensure_response($formatted);
}

function abdp_get_high_traffic_bots($request) {
    $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
    $formatted = array_map(function($entry) {
        return array(
            'ip' => esc_html($entry['ip']),
            'user_agent' => esc_html($entry['user_agent']),
            'timestamp' => esc_html(wp_date('Y-m-d H:i:s', $entry['timestamp'])),
        );
    }, $high_traffic_bots);
    return rest_ensure_response($formatted);
}

// Register settings
add_action('admin_init', 'abdp_register_settings');
function abdp_register_settings() {
    register_setting('abdp_settings_group', 'abdp_max_requests', 'absint');
    register_setting('abdp_settings_group', 'abdp_time_window', 'absint');
    register_setting('abdp_settings_group', 'abdp_ban_threshold', 'absint');
    register_setting('abdp_settings_group', 'abdp_ban_duration', 'absint');
    register_setting('abdp_settings_group', 'abdp_bot_max_requests', 'absint');
    register_setting('abdp_settings_group', 'abdp_log_expires_days', 'absint');
    register_setting('abdp_settings_group', 'abdp_excluded_bots', 'sanitize_textarea_field');
    register_setting('abdp_settings_group', 'abdp_blocked_bots', 'sanitize_textarea_field');
    register_setting('abdp_settings_group', 'abdp_bot_ip_ranges', 'sanitize_textarea_field');
    register_setting('abdp_settings_group', 'abdp_blocked_ips', array(
        'sanitize_callback' => 'abdp_sanitize_blocked_ips',
    ));
    register_setting('abdp_settings_group', 'abdp_banned_ips', array(
        'sanitize_callback' => 'abdp_sanitize_banned_ips',
    ));
    register_setting('abdp_settings_group', 'abdp_high_traffic_bots', array(
        'sanitize_callback' => 'abdp_sanitize_high_traffic_bots',
    ));
}

// Sanitize blocked IPs
function abdp_sanitize_blocked_ips($input) {
    if (!is_array($input)) {
        return array();
    }
    $sanitized = array();
    foreach ($input as $entry) {
        if (isset($entry['ip'], $entry['user_agent'], $entry['timestamp']) && filter_var($entry['ip'], FILTER_VALIDATE_IP) && is_string($entry['user_agent']) && is_numeric($entry['timestamp'])) {
            $sanitized[] = array(
                'ip' => $entry['ip'],
                'user_agent' => sanitize_text_field($entry['user_agent']),
                'timestamp' => absint($entry['timestamp']),
            );
        }
    }
    return $sanitized;
}

// Sanitize banned IPs
function abdp_sanitize_banned_ips($input) {
    if (!is_array($input)) {
        return array();
    }
    $sanitized = array();
    foreach ($input as $entry) {
        if (isset($entry['ip'], $entry['user_agent'], $entry['timestamp'], $entry['expires']) && filter_var($entry['ip'], FILTER_VALIDATE_IP) && is_string($entry['user_agent']) && is_numeric($entry['timestamp']) && is_numeric($entry['expires'])) {
            $sanitized[] = array(
                'ip' => $entry['ip'],
                'user_agent' => sanitize_text_field($entry['user_agent']),
                'timestamp' => absint($entry['timestamp']),
                'expires' => absint($entry['expires']),
            );
        }
    }
    return $sanitized;
}

// Sanitize high traffic bots
function abdp_sanitize_high_traffic_bots($input) {
    if (!is_array($input)) {
        return array();
    }
    $sanitized = array();
    foreach ($input as $entry) {
        if (isset($entry['ip'], $entry['user_agent'], $entry['timestamp']) && filter_var($entry['ip'], FILTER_VALIDATE_IP) && is_string($entry['user_agent']) && is_numeric($entry['timestamp'])) {
            $sanitized[] = array(
                'ip' => $entry['ip'],
                'user_agent' => sanitize_text_field($entry['user_agent']),
                'timestamp' => absint($entry['timestamp']),
            );
        }
    }
    return $sanitized;
}

// Early bot blocking logic to bypass caching
add_action('plugins_loaded', 'abdp_block_bots_early', 1);
function abdp_block_bots_early() {
    // Skip if in admin, AJAX, CRON, or REST API to avoid interference
    if (is_admin() || 
        (defined('DOING_AJAX') && DOING_AJAX) || 
        (defined('DOING_CRON') && DOING_CRON) ||
        (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-json/') !== false)) {
        return;
    }

    $ip = abdp_get_real_ip();
    if (empty($ip)) {
        error_log('ABDP Early: No valid IP detected');
        return;
    }

    $user_agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '');
    error_log('ABDP Early: Processing request. URI: ' . ($_SERVER['REQUEST_URI'] ?? 'unknown') . ', IP: ' . $ip . ', User Agent: ' . $user_agent);

    // Check for blocked bots by User Agent
    if (abdp_is_blocked_bot($user_agent)) {
        error_log('ABDP Early: Blocked bot detected - IP: ' . $ip . ', User Agent: ' . $user_agent);
        $blocked_ips = get_option('abdp_blocked_ips', array());
        $blocked_ips[] = array(
            'ip' => $ip,
            'user_agent' => $user_agent,
            'timestamp' => time(),
        );
        update_option('abdp_blocked_ips', $blocked_ips);
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/html');
        echo '<p style="color: #d32f2f; font-weight: bold; margin: 10px 0;"><b>Anti Browser DDoS Protection</b>: Blocked Bot Access Denied</p>';
        echo '<p style="margin: 10px 0;">Visit GitHub Repository: <a href="https://github.com/sourcecode347/anti-browser-ddos-protection" target="_blank" style="color: #0073aa; text-decoration: underline;">Anti Browser DDoS Protection</a></p>';
        exit;
    }
}

// Rate limiting logic
add_action('init', 'abdp_rate_limit', 1);
function abdp_rate_limit() {
    // Log the request details for debugging
    error_log('ABDP: Processing request. URI: ' . ($_SERVER['REQUEST_URI'] ?? 'unknown') . ', IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'none') . ', Raw User Agent: ' . ($_SERVER['HTTP_USER_AGENT'] ?? 'none'));

    $ip = abdp_get_real_ip();
    if (empty($ip)) {
        error_log('ABDP: No valid IP detected');
        return;
    }

    $user_agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '');
    error_log('ABDP: Processing request for IP: ' . $ip . ', Sanitized User Agent: ' . $user_agent);

    // Skip rate limiting for admin, AJAX, CRON, REST API, static assets, or non-subscriber logged-in users
    if (is_admin() || 
        (defined('DOING_AJAX') && DOING_AJAX) || 
        (defined('DOING_CRON') && DOING_CRON) ||
        (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-json/') !== false) ||
        abdp_is_static_request() ||
        (is_user_logged_in() && !current_user_can('subscriber'))) {
        error_log('ABDP: Rate limiting skipped for request: ' . ($_SERVER['REQUEST_URI'] ?? 'unknown') . ', User Agent: ' . $user_agent);
        return;
    }

    // Check if the user agent is an excluded bot with verified IP
    if (abdp_is_excluded_bot() && !abdp_is_suspicious_bot($ip, $user_agent)) {
        error_log('ABDP: Verified excluded bot - IP: ' . $ip . ', User Agent: ' . $user_agent);
        // Rate limiting for verified excluded bots
        $bot_transient_key = 'abdp_bot_' . md5($ip);
        $bot_request_count = get_transient($bot_transient_key);
        $bot_max_requests = get_option('abdp_bot_max_requests', 100);
        $bot_time_window = 60; // Fixed to 1 minute for bots

        if ($bot_request_count === false) {
            set_transient($bot_transient_key, 1, $bot_time_window);
        } else {
            if ($bot_request_count >= $bot_max_requests) {
                // Log high traffic bot
                error_log('ABDP: High traffic bot detected - IP: ' . $ip . ', User Agent: ' . $user_agent);
                $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
                $high_traffic_bots[] = array(
                    'ip' => $ip,
                    'user_agent' => $user_agent,
                    'timestamp' => time(),
                );
                update_option('abdp_high_traffic_bots', $high_traffic_bots);
            } else {
                set_transient($bot_transient_key, $bot_request_count + 1, $bot_time_window);
            }
        }
        return; // Skip regular rate limiting for verified bots
    }

    // Log suspicious bot to blocked IPs log
    if (abdp_is_suspicious_bot($ip, $user_agent)) {
        error_log('ABDP: Suspicious bot detected - IP: ' . $ip . ', User Agent: ' . $user_agent);
        $blocked_ips = get_option('abdp_blocked_ips', array());
        $blocked_ips[] = array(
            'ip' => $ip,
            'user_agent' => $user_agent,
            'timestamp' => time(),
        );
        update_option('abdp_blocked_ips', $blocked_ips);
    }

    // Check if IP is banned
    $banned_ips = get_option('abdp_banned_ips', array());
    foreach ($banned_ips as $entry) {
        if ($entry['ip'] === $ip && $entry['expires'] > time()) {
            error_log('ABDP: Banned IP detected - IP: ' . $ip . ', User Agent: ' . $user_agent);
                header('HTTP/1.1 403 Forbidden');
                header('Content-Type: text/html');
                echo '<p style="color: #d32f2f; font-weight: bold; margin: 10px 0;"><b>Anti Browser DDoS Protection</b>: Your IP has been banned due to repeated excessive requests.</p>';
                echo '<p style="margin: 10px 0;">Visit GitHub Repository: <a href="https://github.com/sourcecode347/anti-browser-ddos-protection" target="_blank" style="color: #0073aa; text-decoration: underline;">Anti Browser DDoS Protection</a></p>';
                exit;
        }
    }

    $transient_key = 'abdp_' . md5($ip);
    $request_count = get_transient($transient_key);
    $max_requests = get_option('abdp_max_requests', 10);
    $time_window = get_option('abdp_time_window', 60);

    if ($request_count === false) {
        set_transient($transient_key, 1, $time_window);
    } else {
        if ($request_count >= $max_requests) {
            // Log blocked IP
            error_log('ABDP: Rate limit exceeded - IP: ' . $ip . ', User Agent: ' . $user_agent);
            $blocked_ips = get_option('abdp_blocked_ips', array());
            $blocked_ips[] = array(
                'ip' => $ip,
                'user_agent' => $user_agent,
                'timestamp' => time(),
            );
            update_option('abdp_blocked_ips', $blocked_ips);

            // Increment block count
            $block_count_key = 'abdp_block_count_' . md5($ip);
            $block_count = get_transient($block_count_key);
            if ($block_count === false) {
                $block_count = 1;
            } else {
                $block_count++;
            }
            set_transient($block_count_key, $block_count, 24 * HOUR_IN_SECONDS); // Store block count for 24 hours

            // Check if ban threshold is reached
            $ban_threshold = get_option('abdp_ban_threshold', 30);
            $ban_duration = get_option('abdp_ban_duration', 24) * HOUR_IN_SECONDS;
            if ($block_count >= $ban_threshold) {
                error_log('ABDP: Ban threshold reached - IP: ' . $ip . ', User Agent: ' . $user_agent);
                $banned_ips = get_option('abdp_banned_ips', array());
                $banned_ips[] = array(
                    'ip' => $ip,
                    'user_agent' => $user_agent,
                    'timestamp' => time(),
                    'expires' => time() + $ban_duration,
                );
                update_option('abdp_banned_ips', $banned_ips);
                // Clear block count transient
                delete_transient($block_count_key);
                header('HTTP/1.1 403 Forbidden');
                header('Content-Type: text/html');
                echo '<p style="color: #d32f2f; font-weight: bold; margin: 10px 0;"><b>Anti Browser DDoS Protection</b>: Your IP has been banned due to repeated excessive requests.</p>';
                echo '<p style="margin: 10px 0;">Visit GitHub Repository: <a href="https://github.com/sourcecode347/anti-browser-ddos-protection" target="_blank" style="color: #0073aa; text-decoration: underline;">Anti Browser DDoS Protection</a></p>';
                exit;
            }
            header('HTTP/1.1 429 Too Many Requests');
            header('Retry-After: ' . absint($time_window));
            header('Content-Type: text/html');
            echo '<p style="color: #d32f2f; font-weight: bold; margin: 10px 0;"><b>Anti Browser DDoS Protection</b>: Too many requests. Please slow down.</p>';
            echo '<p style="margin: 10px 0;">Visit GitHub Repository: <a href="https://github.com/sourcecode347/anti-browser-ddos-protection" target="_blank" style="color: #0073aa; text-decoration: underline;">Anti Browser DDoS Protection</a></p>';
            exit;
        } else {
            set_transient($transient_key, $request_count + 1, $time_window);
        }
    }
}

function abdp_is_excluded_bot() {
    if (!isset($_SERVER['HTTP_USER_AGENT'])) {
        return false;
    }
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $excluded_bots = get_option('abdp_excluded_bots', '');
    if (empty($excluded_bots)) {
        return false;
    }
    
    $bot_list = array_filter(array_map('trim', explode("\n", $excluded_bots)));
    
    foreach ($bot_list as $bot) {
        if (!empty($bot) && stripos($user_agent, $bot) !== false) {
            return true;
        }
    }
    return false;
}

function abdp_is_static_request() {
    if (!isset($_SERVER['REQUEST_URI'])) {
        return false;
    }
    $uri = $_SERVER['REQUEST_URI'];
    return preg_match('/\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|pdf|zip|mp4|webm)$/i', $uri);
}

// Clean up transients and logs on deactivation
register_deactivation_hook(__FILE__, 'abdp_deactivate');
function abdp_deactivate() {
    // Use WP API to delete options (no direct query needed)
    delete_option('abdp_blocked_ips');
    delete_option('abdp_banned_ips');
    delete_option('abdp_blocked_bots');
    delete_option('abdp_bot_ip_ranges');
    delete_option('abdp_high_traffic_bots');
    delete_option('abdp_log_expires_days');

    // Clear scheduled log cleanup event
    wp_clear_scheduled_hook('abdp_cleanup_logs_event');

    // Flush transients using WP functions (covers object cache)
    wp_cache_flush(); // Clears all object cache, including transients
}