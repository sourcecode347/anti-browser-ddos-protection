<?php
/*
Plugin Name: Anti Browser DDoS Protection
Description: Rate limiting with admin panel, bot exclusions, bot IP ranges management with duplicate removal, high traffic bot logging, static asset exclusion, blocked IP logging with User Agent, IP banning with User Agent, Cloudflare real IP support, blocked bots by User Agent, auto-refresh logs every 30 seconds, automatic log expiration, and export/import for bot lists.
Version: 2.26
Author: sourcecode347
License: GPL v2 or later
Text Domain: anti-browser-ddos-protection
*/

if (!defined('ABSPATH')) {
    exit;
}

// Cloudflare IP ranges (IPv4 and IPv6)
function abdp_is_cloudflare_ip($ip) {
    $cloudflare_ranges = array(
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
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    );

    foreach ($cloudflare_ranges as $range) {
        if (abdp_cidr_match($ip, $range)) {
            return true;
        }
    }
    return false;
}

// Get real client IP (Cloudflare support)
function abdp_get_real_ip() {
    $ip = sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '');

    if (abdp_is_cloudflare_ip($ip)) {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])), FILTER_VALIDATE_IP)) {
            return sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded_ips = array_map('trim', explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']))));
            $first_ip = filter_var($forwarded_ips[0] ?? '', FILTER_VALIDATE_IP) ? $forwarded_ips[0] : '';
            if ($first_ip) {
                return $first_ip;
            }
        }
    }
    return $ip;
}

// Helper function for CIDR matching (IPv4 and IPv6)
function abdp_cidr_match($ip, $range) {
    list($subnet, $bits) = explode('/', $range);
    $bits = (int) $bits;

    if ($bits < 0 || $bits > 128) {
        return false;
    }

    $ip_bin = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);

    if ($ip_bin === false || $subnet_bin === false) {
        return false;
    }

    $addr_len = strlen($ip_bin);

    if ($addr_len !== strlen($subnet_bin)) {
        return false;
    }

    $full_bytes = (int) ($bits / 8);
    $partial_bits = $bits % 8;

    $mask = str_repeat("\xFF", $full_bytes);
    if ($partial_bits > 0) {
        $mask .= chr(0xFF << (8 - $partial_bits));
    }
    $mask .= str_repeat("\0", $addr_len - strlen($mask));

    return ($ip_bin & $mask) === ($subnet_bin & $mask);
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

// Check if IP belongs to known bot IP ranges (IPv4/IPv6 support)
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

    $bot_ip_ranges = get_option('abdp_bot_ip_ranges', '');
    if (empty($bot_ip_ranges)) {
        return true;
    }

    $known_bot_ranges = array_filter(array_map('trim', explode("\n", $bot_ip_ranges)));

    foreach ($known_bot_ranges as $range) {
        if (abdp_cidr_match($ip, $range)) {
            return false;
        }
    }

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

// Set cookie with sanitized domain
$server_name = sanitize_text_field($_SERVER['SERVER_NAME'] ?? '');
setcookie("abdp_admin_notice", "0", time() + (86400 * 30), "/", $server_name);

// Admin notice to confirm menu registration
add_action('admin_notices', 'abdp_admin_notice');
function abdp_admin_notice() {
    if (!current_user_can('manage_options')) {
        return;
    }
    if (!isset($_COOKIE['abdp_admin_notice'])) {
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
    // Get the log expiration days setting
    $log_expires_days = absint(get_option('abdp_log_expires_days', 5));
    $expiration_time = time() - ($log_expires_days * DAY_IN_SECONDS);

    // Clean up blocked_ips
    $blocked_ips = get_option('abdp_blocked_ips', array());
    $blocked_ips = array_filter($blocked_ips, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time;
    });
    update_option('abdp_blocked_ips', array_values($blocked_ips));

    // Clean up banned_ips
    $banned_ips = get_option('abdp_banned_ips', array());
    $banned_ips = array_filter($banned_ips, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time && $entry['expires'] > time();
    });
    update_option('abdp_banned_ips', array_values($banned_ips));

    // Clean up high_traffic_bots
    $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
    $high_traffic_bots = array_filter($high_traffic_bots, function($entry) use ($expiration_time) {
        return $entry['timestamp'] >= $expiration_time;
    });
    update_option('abdp_high_traffic_bots', array_values($high_traffic_bots));

    // Log for debugging purposes
    error_log('ABDP Cleanup Logs ran at ' . date('Y-m-d H:i:s'));
}

// Schedule log cleanup
function abdp_schedule_log_cleanup() {
    if (!wp_next_scheduled('abdp_cleanup_logs_event')) {
        wp_schedule_event(time(), 'hourly', 'abdp_cleanup_logs_event');
        error_log('ABDP Cleanup Logs event scheduled at ' . date('Y-m-d H:i:s'));
    }
}

// Schedule cleanup on plugin activation
register_activation_hook(__FILE__, 'abdp_schedule_log_cleanup');

// Clear scheduled event on plugin deactivation
function abdp_deactivate_cleanup() {
    wp_clear_scheduled_hook('abdp_cleanup_logs_event');
}
register_deactivation_hook(__FILE__, 'abdp_deactivate_cleanup');

// Ensure the event is scheduled on every page load
add_action('init', function() {
    if (!wp_next_scheduled('abdp_cleanup_logs_event')) {
        abdp_schedule_log_cleanup();
    }
});

// Hook for executing the cleanup
add_action('abdp_cleanup_logs_event', 'abdp_cleanup_expired_logs');

// AJAX handler for refreshing nonce
add_action('wp_ajax_abdp_refresh_nonce', 'abdp_refresh_nonce');
function abdp_refresh_nonce() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized', 403);
    }
    wp_send_json_success(wp_create_nonce('wp_rest'));
}

// Enqueue assets on the settings page
add_action('admin_enqueue_scripts', 'abdp_enqueue_scripts');
function abdp_enqueue_scripts($hook) {
    if ($hook !== 'settings_page_abdp-settings') {
        return;
    }

    wp_enqueue_script('chart-js', plugin_dir_url(__FILE__) . 'assets/js/chart.umd.min.js', array(), '4.4.4', true);

    if (wp_is_mobile()) {
        wp_enqueue_style('abdp-admin-mobile-css', plugin_dir_url(__FILE__) . 'assets/css/abdp-admin-mobile.css', array(), '1.0');
    } else {
        wp_enqueue_style('abdp-admin-css', plugin_dir_url(__FILE__) . 'assets/css/abdp-admin.css', array(), '1.0');
    }

    wp_enqueue_script('abdp-admin-js', plugin_dir_url(__FILE__) . 'assets/js/abdp-admin.js', array('chart-js'), '1.0', true);

    wp_localize_script('abdp-admin-js', 'abdpData', array(
        'apiBase' => esc_url(rest_url('abdp/v1')),
        'nonce' => wp_create_nonce('wp_rest'),
        'ajaxUrl' => esc_url(admin_url('admin-ajax.php')),
        'logExpiresDays' => absint(get_option('abdp_log_expires_days', 5)),
    ));
}

// Export handlers
add_action('admin_post_abdp_export_excluded_bots', 'abdp_export_excluded_bots');
function abdp_export_excluded_bots() {
    $nonce = isset($_GET['nonce']) ? sanitize_text_field(wp_unslash($_GET['nonce'])) : '';
    if (!current_user_can('manage_options') || !wp_verify_nonce($nonce, 'abdp_export_excluded_bots')) {
        wp_die('Unauthorized', 'Forbidden', array('response' => 403));
    }
    $data = get_option('abdp_excluded_bots', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="excluded_bots.txt"');
    echo esc_html($data);
    exit;
}

add_action('admin_post_abdp_export_bot_ip_ranges', 'abdp_export_bot_ip_ranges');
function abdp_export_bot_ip_ranges() {
    $nonce = isset($_GET['nonce']) ? sanitize_text_field(wp_unslash($_GET['nonce'])) : '';
    if (!current_user_can('manage_options') || !wp_verify_nonce($nonce, 'abdp_export_bot_ip_ranges')) {
        wp_die('Unauthorized', 'Forbidden', array('response' => 403));
    }
    $data = get_option('abdp_bot_ip_ranges', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="bot_ip_ranges.txt"');
    echo esc_html($data);
    exit;
}

add_action('admin_post_abdp_export_blocked_bots', 'abdp_export_blocked_bots');
function abdp_export_blocked_bots() {
    $nonce = isset($_GET['nonce']) ? sanitize_text_field(wp_unslash($_GET['nonce'])) : '';
    if (!current_user_can('manage_options') || !wp_verify_nonce($nonce, 'abdp_export_blocked_bots')) {
        wp_die('Unauthorized', 'Forbidden', array('response' => 403));
    }
    $data = get_option('abdp_blocked_bots', '');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="blocked_bots.txt"');
    echo esc_html($data);
    exit;
}

// Settings page
function abdp_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized', 'Forbidden', array('response' => 403));
    }

    if (isset($_POST['abdp_save_settings'])) {
        check_admin_referer('abdp_save_settings');

        // Handle imports
        if (!empty($_FILES['abdp_excluded_bots_file']['name'])) {
            $file_content = sanitize_textarea_field(file_get_contents($_FILES['abdp_excluded_bots_file']['tmp_name']));
            $new_lines = array_filter(array_map('sanitize_text_field', array_map('trim', explode("\n", $file_content))));
            $current_lines = array_filter(array_map('sanitize_text_field', array_map('trim', explode("\n", sanitize_textarea_field(wp_unslash($_POST['abdp_excluded_bots'] ?? ''))))));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_excluded_bots'] = implode("\n", $all_lines);
        }

        if (!empty($_FILES['abdp_bot_ip_ranges_file']['name'])) {
            $file_content = sanitize_textarea_field(file_get_contents($_FILES['abdp_bot_ip_ranges_file']['tmp_name']));
            $new_lines = array_filter(array_map('trim', explode("\n", $file_content)));
            $new_lines = array_filter($new_lines, function($line) {
                return preg_match('/^([0-9a-fA-F.:]+)\/([0-9]{1,3})$/', $line); // Validate CIDR
            });
            $current_lines = array_filter(array_map('trim', explode("\n", sanitize_textarea_field(wp_unslash($_POST['abdp_bot_ip_ranges'] ?? '')))));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_bot_ip_ranges'] = implode("\n", $all_lines);
        }

        if (!empty($_FILES['abdp_blocked_bots_file']['name'])) {
            $file_content = sanitize_textarea_field(file_get_contents($_FILES['abdp_blocked_bots_file']['tmp_name']));
            $new_lines = array_filter(array_map('sanitize_text_field', array_map('trim', explode("\n", $file_content))));
            $current_lines = array_filter(array_map('sanitize_text_field', array_map('trim', explode("\n", sanitize_textarea_field(wp_unslash($_POST['abdp_blocked_bots'] ?? ''))))));
            $all_lines = array_unique(array_merge($current_lines, $new_lines));
            $_POST['abdp_blocked_bots'] = implode("\n", $all_lines);
        }

        $raw_bot_ip_ranges = sanitize_textarea_field(wp_unslash($_POST['abdp_bot_ip_ranges'] ?? ''));
        $bot_ip_ranges_array = array_filter(array_map('trim', explode("\n", $raw_bot_ip_ranges)));
        $unique_bot_ip_ranges = array_filter(array_unique($bot_ip_ranges_array), function($line) {
            return preg_match('/^([0-9a-fA-F.:]+)\/([0-9]{1,3})$/', $line); // Validate CIDR
        });
        $cleaned_bot_ip_ranges = implode("\n", $unique_bot_ip_ranges);

        update_option('abdp_max_requests', absint($_POST['abdp_max_requests'] ?? 10));
        update_option('abdp_time_window', absint($_POST['abdp_time_window'] ?? 60));
        update_option('abdp_excluded_bots', sanitize_textarea_field(wp_unslash($_POST['abdp_excluded_bots'] ?? '')));
        update_option('abdp_blocked_bots', sanitize_textarea_field(wp_unslash($_POST['abdp_blocked_bots'] ?? '')));
        update_option('abdp_bot_ip_ranges', $cleaned_bot_ip_ranges);
        update_option('abdp_ban_threshold', absint($_POST['abdp_ban_threshold'] ?? 30));
        update_option('abdp_ban_duration', absint($_POST['abdp_ban_duration'] ?? 24));
        update_option('abdp_bot_max_requests', absint($_POST['abdp_bot_max_requests'] ?? 100));
        update_option('abdp_log_expires_days', absint($_POST['abdp_log_expires_days'] ?? 5));
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Settings saved successfully! Duplicate IP ranges have been removed.', 'anti-browser-ddos-protection') . '</p></div>';
    }

    if (isset($_POST['abdp_clear_blocked_log'])) {
        check_admin_referer('abdp_clear_blocked_log');
        delete_option('abdp_blocked_ips');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Blocked IPs log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    if (isset($_POST['abdp_clear_banned_log'])) {
        check_admin_referer('abdp_clear_banned_log');
        delete_option('abdp_banned_ips');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Banned IPs log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    if (isset($_POST['abdp_clear_high_traffic_bots_log'])) {
        check_admin_referer('abdp_clear_high_traffic_bots_log');
        delete_option('abdp_high_traffic_bots');
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('High Traffic Bots log cleared successfully!', 'anti-browser-ddos-protection') . '</p></div>';
    }

    $max_requests = absint(get_option('abdp_max_requests', 10));
    $time_window = absint(get_option('abdp_time_window', 60));
    $ban_threshold = absint(get_option('abdp_ban_threshold', 30));
    $ban_duration = absint(get_option('abdp_ban_duration', 24));
    $bot_max_requests = absint(get_option('abdp_bot_max_requests', 100));
    $log_expires_days = absint(get_option('abdp_log_expires_days', 5));
    $excluded_bots = get_option('abdp_excluded_bots', "Googlebot\nBingbot\nSlurp\nDuckDuckBot\nTwitterbot\nMediapartners-Google\nGoogle-Display-Ads-Bot\nAdsBot\nfacebookexternalhit\nAdsBot-Google\nAppEngine-Google\nFeedfetcher-Google\nYandex\nAhrefsBot\nmsnbot\nbingbot\nStripebot");
    $blocked_bots = get_option('abdp_blocked_bots', "MJ12bot\nSemrushBot\nDotBot");
    $bot_ip_ranges = get_option('abdp_bot_ip_ranges', implode("\n", array(
        '66.249.64.0/19', '66.249.80.0/20', '66.249.92.0/23', '66.249.94.0/23', '66.249.93.0/24',
        '64.233.160.0/19', '64.233.161.0/24', '64.233.162.0/24', '64.233.163.0/24', '64.233.166.0/24',
        '64.233.167.0/24', '64.233.168.0/24', '64.233.169.0/24', '64.233.170.0/24', '64.233.171.0/24',
        '64.233.172.0/24', '64.233.173.0/24', '64.233.174.0/24', '64.233.175.0/24', '64.233.176.0/24',
        '64.233.177.0/24', '64.233.178.0/24', '64.233.179.0/24', '64.233.180.0/24', '64.233.181.0/24',
        '64.233.182.0/24', '64.233.183.0/24', '64.233.184.0/24', '64.233.185.0/24', '64.233.186.0/24',
        '64.233.187.0/24', '64.233.188.0/24', '64.233.189.0/24', '64.233.190.0/24', '64.233.191.0/24',
        '72.14.192.0/18', '72.14.203.0/24', '72.14.204.0/24', '72.14.205.0/24', '72.14.206.0/24',
        '72.14.207.0/24', '74.125.0.0/16', '108.177.8.0/21', '108.177.96.0/19', '172.217.0.0/19',
        '172.217.32.0/20', '172.217.128.0/19', '172.217.160.0/20', '172.217.169.0/24', '172.217.170.0/24',
        '172.217.171.0/24', '172.217.172.0/24', '172.217.173.0/24', '172.217.174.0/24', '172.217.175.0/24',
        '172.217.176.0/20', '172.217.192.0/19', '172.253.0.0/16', '173.194.0.0/16', '209.85.128.0/17',
        '216.58.192.0/19', '216.58.224.0/20', '216.239.32.0/19', '216.239.34.0/24', '216.239.36.0/24',
        '216.239.38.0/24', '157.55.0.0/16', '157.56.0.0/14', '204.79.180.0/24', '204.79.181.0/24',
        '204.79.182.0/24', '204.79.183.0/24', '204.79.184.0/24', '204.79.185.0/24', '204.79.186.0/24',
        '204.79.187.0/24', '40.77.0.0/16', '52.114.0.0/15', '64.4.0.0/18', '65.52.0.0/14',
        '94.245.0.0/17', '111.221.16.0/22', '111.221.29.0/24', '131.253.0.0/16', '131.253.21.0/24',
        '131.253.22.0/24', '131.253.23.0/24', '131.253.33.0/24', '131.253.34.0/24', '131.253.35.0/24',
        '131.253.37.0/24', '131.253.39.0/24', '157.54.0.0/15', '157.60.0.0/16', '168.61.0.0/16',
        '191.234.0.0/17', '199.47.87.0/24', '207.46.0.0/16', '67.195.37.0/24', '67.195.52.0/24',
        '67.195.53.0/24', '67.195.54.0/24', '67.195.55.0/24', '69.147.64.0/18', '69.147.80.0/20',
        '69.164.208.0/20', '69.164.224.0/19', '72.30.0.0/16', '74.6.17.0/24', '74.6.18.0/23',
        '74.6.20.0/24', '98.136.0.0/16', '98.137.0.0/16', '98.138.0.0/16', '202.160.176.0/22',
        '23.21.150.121/32', '40.88.24.0/24', '43.249.72.0/22', '50.16.0.0/16', '50.19.0.0/16',
        '52.70.160.0/20', '54.166.128.0/17', '54.236.0.0/15', '54.242.0.0/14', '107.22.0.0/15',
        '107.23.0.0/16', '149.20.64.0/18', '162.216.0.0/18', '185.185.186.0/24', '199.16.156.0/22',
        '199.59.148.0/22', '104.244.42.0/24', '104.244.75.0/24', '104.244.76.0/24', '104.244.78.0/24',
        '104.244.79.0/24', '31.13.24.0/21', '31.13.64.0/18', '69.63.176.0/20', '69.171.224.0/20',
        '74.119.0.0/16', '102.132.96.0/20', '129.134.0.0/16', '157.240.0.0/16', '173.252.64.0/18',
        '185.60.216.0/22', '185.89.216.0/22', '5.45.192.0/22', '5.45.196.0/23', '5.45.198.0/23',
        '5.45.200.0/21', '5.255.192.0/20', '77.88.0.0/20', '77.88.16.0/21', '87.250.224.0/20',
        '87.250.240.0/21', '93.158.128.0/20', '93.158.144.0/20', '93.158.160.0/20', '93.158.176.0/20',
        '109.70.128.0/18', '141.8.128.0/20', '141.8.144.0/20', '141.8.160.0/20', '141.8.176.0/20',
        '178.154.192.0/20', '178.154.208.0/20', '178.154.224.0/20', '178.154.240.0/20', '213.180.192.0/20',
        '213.180.208.0/20', '151.101.1.164/32', '151.101.65.164/32', '151.101.129.164/32', '151.101.193.164/32',
        '151.101.2.164/32', '151.101.66.164/32', '151.101.130.164/32', '151.101.194.164/32', '151.101.3.164/32',
        '151.101.67.164/32', '151.101.131.164/32', '151.101.195.164/32', '151.101.0.164/32', '151.101.64.164/32',
        '151.101.128.164/32', '151.101.192.164/32', '3.18.36.0/24', '3.19.0.0/16', '18.188.0.0/15',
        '52.94.0.0/18', '54.218.0.0/16',
    )));
    $blocked_ips = get_option('abdp_blocked_ips', array());
    $banned_ips = get_option('abdp_banned_ips', array());
    $high_traffic_bots = get_option('abdp_high_traffic_bots', array());
    ?>
    <div class="wrap">
        <div class="abdp-header">
            <div class="abdp-donate-link">
                <?php 
                    printf(
                        esc_html__('Support this project with one %s', 'anti-browser-ddos-protection'),
                        '<a href="https://buy.stripe.com/bIY5o70SSfam8Qo7ss" target="_blank">' . esc_html__('Donate', 'anti-browser-ddos-protection') . '</a>'
                    ); 
                ?>
            </div>
            <div class="abdp-logo">
                <?php
                    $logo_url = plugin_dir_url(__FILE__) . 'assets/img/Anti-Browser-DDoS-Protection.png';
                    printf(
                        '<img src="%s" alt="%s" class="abdp-logo-img"/>',
                        esc_url($logo_url),
                        esc_attr__('Anti Browser DDoS Protection Logo', 'anti-browser-ddos-protection')
                    );
                ?>
            </div>
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
                        <p class="description"><?php echo esc_html__('One IP range per line in CIDR format (e.g., 66.249.64.0/19 or 2400:cb00::/32). Verified IP Ranges for Excluded Bots.', 'anti-browser-ddos-protection'); ?></p>
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
                <?php 
                    wp_nonce_field('abdp_clear_blocked_log');
                    submit_button(esc_html__('Clear Blocked IPs Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_blocked_log'); 
                ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('No blocked IPs recorded yet.', 'anti-browser-ddos-protection'); ?></p>
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
                <?php 
                    wp_nonce_field('abdp_clear_banned_log');
                    submit_button(esc_html__('Clear Banned IPs Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_banned_log'); 
                ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('No banned IPs recorded yet.', 'anti-browser-ddos-protection'); ?></p>
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
                <?php 
                    wp_nonce_field('abdp_clear_high_traffic_bots_log');
                    submit_button(esc_html__('Clear High Traffic Bots Log', 'anti-browser-ddos-protection'), 'secondary', 'abdp_clear_high_traffic_bots_log'); 
                ?>
            </form>
        <?php else : ?>
            <p><?php echo esc_html__('No high traffic bots recorded yet.', 'anti-browser-ddos-protection'); ?></p>
        <?php endif; ?>
    </div>
    <?php
}

// Register REST API endpoints
add_action('rest_api_init', 'abdp_register_rest_endpoints');
function abdp_register_rest_endpoints() {
    register_rest_route('abdp/v1', '/blocked-ips', array(
        'methods' => 'GET',
        'callback' => 'abdp_get_blocked_ips',
        'permission_callback' => function() {
            return current_user_can('manage_options');
        },
    ));

    register_rest_route('abdp/v1', '/banned-ips', array(
        'methods' => 'GET',
        'callback' => 'abdp_get_banned_ips',
        'permission_callback' => function() {
            return current_user_can('manage_options');
        },
    ));

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
    register_setting('abdp_settings_group', 'abdp_excluded_bots', array(
        'sanitize_callback' => 'sanitize_textarea_field',
    ));
    register_setting('abdp_settings_group', 'abdp_blocked_bots', array(
        'sanitize_callback' => 'sanitize_textarea_field',
    ));
    register_setting('abdp_settings_group', 'abdp_bot_ip_ranges', array(
        'sanitize_callback' => function($input) {
            $lines = array_filter(array_map('trim', explode("\n", sanitize_textarea_field($input))));
            $valid_lines = array_filter($lines, function($line) {
                return preg_match('/^([0-9a-fA-F.:]+)\/([0-9]{1,3})$/', $line);
            });
            return implode("\n", array_unique($valid_lines));
        },
    ));
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

// Rate limiting logic
add_action('wp_loaded', 'abdp_rate_limit', 1);
function abdp_rate_limit() {
    $ip = abdp_get_real_ip();
    if (empty($ip)) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('ABDP: No valid IP detected');
        }
        return;
    }

    $user_agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('ABDP: Processing request for IP: ' . esc_html($ip) . ', Sanitized User Agent: ' . esc_html($user_agent));
    }

    if (is_admin() || 
        (defined('DOING_AJAX') && DOING_AJAX) || 
        (defined('DOING_CRON') && DOING_CRON) ||
        (isset($_SERVER['REQUEST_URI']) && strpos(sanitize_text_field($_SERVER['REQUEST_URI']), '/wp-json/') !== false) ||
        abdp_is_static_request() ||
        (is_user_logged_in() && !current_user_can('subscriber'))) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('ABDP: Rate limiting skipped for request: ' . esc_html(sanitize_text_field($_SERVER['REQUEST_URI'] ?? 'unknown')) . ', User Agent: ' . esc_html($user_agent));
        }
        return;
    }

    if (abdp_is_blocked_bot($user_agent)) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('ABDP: Blocked bot detected - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
        }
        $blocked_ips = get_option('abdp_blocked_ips', array());
        $blocked_ips[] = array(
            'ip' => $ip,
            'user_agent' => $user_agent,
            'timestamp' => time(),
        );
        update_option('abdp_blocked_ips', $blocked_ips);
        status_header(403);
        nocache_headers();
        wp_die('Blocked Bot Access Denied', 'Forbidden', array('response' => 403));
    }

    if (abdp_is_excluded_bot() && !abdp_is_suspicious_bot($ip, $user_agent)) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('ABDP: Verified excluded bot - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
        }
        $bot_transient_key = 'abdp_bot_' . md5($ip);
        $bot_request_count = get_transient($bot_transient_key);
        $bot_max_requests = absint(get_option('abdp_bot_max_requests', 100));
        $bot_time_window = 60;

        if ($bot_request_count === false) {
            set_transient($bot_transient_key, 1, $bot_time_window);
        } else {
            if ($bot_request_count >= $bot_max_requests) {
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('ABDP: High traffic bot detected - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
                }
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
        return;
    }

    if (abdp_is_suspicious_bot($ip, $user_agent)) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('ABDP: Suspicious bot detected - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
        }
        $blocked_ips = get_option('abdp_blocked_ips', array());
        $blocked_ips[] = array(
            'ip' => $ip,
            'user_agent' => $user_agent,
            'timestamp' => time(),
        );
        update_option('abdp_blocked_ips', $blocked_ips);
    }

    $banned_ips = get_option('abdp_banned_ips', array());
    foreach ($banned_ips as $entry) {
        if ($entry['ip'] === $ip && $entry['expires'] > time()) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('ABDP: Banned IP detected - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
            }
            status_header(403);
            nocache_headers();
            wp_die('Your IP has been banned due to repeated excessive requests.', 'Forbidden', array('response' => 403));
        }
    }

    $transient_key = 'abdp_' . md5($ip);
    $request_count = get_transient($transient_key);
    $max_requests = absint(get_option('abdp_max_requests', 10));
    $time_window = absint(get_option('abdp_time_window', 60));

    if ($request_count === false) {
        set_transient($transient_key, 1, $time_window);
    } else {
        if ($request_count >= $max_requests) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('ABDP: Rate limit exceeded - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
            }
            $blocked_ips = get_option('abdp_blocked_ips', array());
            $blocked_ips[] = array(
                'ip' => $ip,
                'user_agent' => $user_agent,
                'timestamp' => time(),
            );
            update_option('abdp_blocked_ips', $blocked_ips);

            $block_count_key = 'abdp_block_count_' . md5($ip);
            $block_count = get_transient($block_count_key);
            if ($block_count === false) {
                $block_count = 1;
            } else {
                $block_count++;
            }
            set_transient($block_count_key, $block_count, 24 * HOUR_IN_SECONDS);

            $ban_threshold = absint(get_option('abdp_ban_threshold', 30));
            $ban_duration = absint(get_option('abdp_ban_duration', 24)) * HOUR_IN_SECONDS;
            if ($block_count >= $ban_threshold) {
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('ABDP: Ban threshold reached - IP: ' . esc_html($ip) . ', User Agent: ' . esc_html($user_agent));
                }
                $banned_ips = get_option('abdp_banned_ips', array());
                $banned_ips[] = array(
                    'ip' => $ip,
                    'user_agent' => $user_agent,
                    'timestamp' => time(),
                    'expires' => time() + $ban_duration,
                );
                update_option('abdp_banned_ips', $banned_ips);
                delete_transient($block_count_key);
                status_header(403);
                nocache_headers();
                wp_die('Your IP has been banned due to repeated excessive requests.', 'Forbidden', array('response' => 403));
            }
            status_header(429);
            header('Retry-After: ' . absint($time_window));
            nocache_headers();
            wp_die('Too many requests. Please slow down.', 'Too Many Requests', array('response' => 429));
        } else {
            set_transient($transient_key, $request_count + 1, $time_window);
        }
    }
}

function abdp_is_excluded_bot() {
    if (!isset($_SERVER['HTTP_USER_AGENT'])) {
        return false;
    }
    $user_agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
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
    $uri = sanitize_text_field($_SERVER['REQUEST_URI']);
    return preg_match('/\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|pdf|zip|mp4|webm|mp3|avif|otf)$/i', $uri);
}

// Clean up on deactivation
register_deactivation_hook(__FILE__, 'abdp_deactivate');
function abdp_deactivate() {
    delete_option('abdp_blocked_ips');
    delete_option('abdp_banned_ips');
    delete_option('abdp_blocked_bots');
    delete_option('abdp_bot_ip_ranges');
    delete_option('abdp_high_traffic_bots');
    delete_option('abdp_log_expires_days');

    wp_clear_scheduled_hook('abdp_cleanup_logs_event');

    wp_cache_flush();
}