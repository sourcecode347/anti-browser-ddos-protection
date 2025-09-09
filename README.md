# anti-browser-ddos-protection
Protect your WordPress site from DDoS attacks with advanced rate limiting, bot detection, automatic duplicate IP range removal, static asset exclusion, IP banning, and Cloudflare optimization.

=== Anti Browser DDoS Protection ===

Author: SourceCode347

Contributors: xAI

Plugin Name: Anti Browser DDoS Protection

Tags: security, ddos-protection, rate-limiting, ip-blocking, cloudflare, bot-detection

Requires at least: 5.0

Tested up to: 6.8

Stable tag: 2.14

License: GPLv2 or later

License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress site from DDoS attacks with advanced rate limiting, bot detection, automatic duplicate IP range removal, static asset exclusion, IP banning, and Cloudflare optimization.

== Description ==

The **Anti Browser DDoS Protection** plugin provides robust protection against denial-of-service (DoS) attacks on your WordPress site. It implements IP-based rate limiting, with configurable settings for subscribers and non-logged-in users, while excluding administrators and other non-subscriber roles. The plugin features advanced bot detection to identify and limit suspicious bots, supports Cloudflare for accurate client IP detection, and excludes static assets (e.g., CSS, JS, images) to maintain site performance. An intuitive admin panel allows you to configure rate limits, bot exclusions, trusted bot IP ranges (with automatic duplicate removal), and view logs for blocked and banned IPs.

**Key Features:**
- Rate limiting based on IP for subscribers and non-logged-in users, with configurable maximum requests and time window.
- Excludes non-subscriber logged-in users (e.g., administrators, editors) from rate limiting.
- Advanced bot detection to identify suspicious bots (bots using trusted User Agents but from unverified IPs).
- Suspicious bots are subject to the same rate limiting as regular users and logged for monitoring.
- Admin panel to configure maximum requests, time window, excluded bots, and trusted bot IP ranges (in CIDR format).
- Automatic removal of duplicate IP ranges in the **Bot IP Ranges** field on save, keeping the first occurrence.
- Support for Cloudflare real IP detection using `CF-Connecting-IP` and `X-Forwarded-For` headers.
- Excludes static assets (CSS, JS, images, fonts, etc.) from rate limiting to optimize performance.
- Logs blocked and banned IPs with timestamps, viewable in the admin panel with options to clear logs.
- Automatic cleanup of transients, blocked IPs, banned IPs, and bot IP ranges on plugin deactivation to prevent database bloat.

Ideal for WordPress sites seeking enhanced security against automated attacks, with seamless integration for Cloudflare users and simplified bot IP range management.

== Installation ==
1. Upload the `anti-ddos-protection` folder to the `/wp-content/plugins/` directory, or install the plugin directly through the WordPress plugins screen.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to **Settings > Anti DDoS** to configure the plugin settings:
   - Set the **Maximum Requests** (e.g., 10 requests).
   - Set the **Time Window** in seconds (e.g., 60 seconds).
   - Add **Excluded Bots** (User Agents, one per line, e.g., Googlebot, Bingbot).
   - Add **Bot IP Ranges** (trusted IP ranges in CIDR format, one per line, e.g., 66.249.64.0/19). Duplicates are automatically removed on save. Update every 6 months (next update: March 2026).
   - Set **Blocks Before Ban** (e.g., 30 blocks) and **Ban Duration** (e.g., 24 hours).
4. Test the rate limiting by sending multiple requests (e.g., refreshing a page rapidly) using a subscriber account or non-logged-in IP to ensure blocking works.
5. Test suspicious bot detection by sending requests with a bot User Agent (e.g., Googlebot) from an unverified IP.
6. Check the **Blocked IPs Log** and **Banned IPs Log** sections in the admin panel to view logs and clear them if needed.

== Frequently Asked Questions ==

= Does this plugin work with Cloudflare? =
Yes, the plugin supports Cloudflare by using the `CF-Connecting-IP` header to detect the real client IP, ensuring accurate rate limiting and logging.

= Can I exclude specific bots from rate limiting? =
Yes, you can add User Agents (e.g., Googlebot, Bingbot) in the **Excluded Bots** field in the admin panel. Bots from trusted IP ranges (configured in **Bot IP Ranges**) are exempt from rate limiting.

= How are suspicious bots handled? =
Bots with trusted User Agents (e.g., Googlebot) but from unverified IPs are flagged as suspicious, logged in the Blocked IPs Log, and subjected to the same rate limiting as regular users (e.g., 10 requests per 60 seconds).

= Can I manage trusted bot IP ranges? =
Yes, you can configure trusted bot IP ranges in the **Bot IP Ranges** field in the admin panel (Settings > Anti DDoS). Enter ranges in CIDR format (e.g., 66.249.64.0/19), one per line. Duplicate ranges are automatically removed on save. Update every 6 months.

= Are static assets like CSS and JS rate-limited? =
No, the plugin excludes common static assets (e.g., .css, .js, .jpg, .png) to prevent performance issues.

= Are logged-in users rate-limited? =
Only users with the `subscriber` role are rate-limited. Administrators, editors, and other non-subscriber roles are exempt.

= How do I view blocked or banned IPs? =
Go to **Settings > Anti DDoS** to see the **Blocked IPs Log** and **Banned IPs Log** tables, which list IPs, timestamps, and ban expiration times. You can clear the logs using the provided buttons.

= What happens when I deactivate the plugin? =
The plugin automatically deletes its transients, blocked IP logs, banned IP logs, and bot IP ranges from the database to prevent bloat.

== Screenshots ==
1. Admin panel under **Settings > Anti DDoS**, showing configuration options for Maximum Requests, Time Window, Excluded Bots, Bot IP Ranges, Blocks Before Ban, and Ban Duration.
2. Blocked IPs Log table, displaying IPs and timestamps with a Clear button.
3. Banned IPs Log table, showing IPs, ban timestamps, and expiration times with a Clear button.
4. Example of the "Too many requests" error page when an IP exceeds the rate limit.
5. Example of the "Forbidden" error page when an IP is banned.

== Changelog ==

= 2.14 =
* Added automatic removal of duplicate IP ranges in the **Bot IP Ranges** field on save, keeping the first occurrence.
* Updated admin panel description to note that duplicate IP ranges are automatically removed.
* Updated success message to confirm duplicate IP range removal.

= 2.13 =
* Added **Bot IP Ranges** field in the admin panel to manage trusted bot IP ranges in CIDR format (e.g., 66.249.64.0/19).
* Moved bot IP ranges from hardcoded list to admin panel for easier updates every 6 months (next update: March 2026).
* Updated suspicious bot handling to use standard rate limiting settings (e.g., 10 requests per 60 seconds).

= 2.12 =
* Updated suspicious bot handling to use standard rate limiting settings instead of stricter limits.
* Added note to update bot IP ranges every 6 months (next update: March 2026).

= 2.11 =
* Added comprehensive list of trusted IP ranges for Googlebot, Bingbot, Slurp, DuckDuckBot, Twitterbot, Mediapartners-Google, Google-Display-Ads-Bot, AdsBot, facebookexternalhit, AdsBot-Google, AppEngine-Google, Feedfetcher-Google, Yandex, AhrefsBot, msnbot, bingbot, and Stripebot.
* Suspicious bots (unverified IPs with trusted User Agents) are logged and subjected to stricter rate limiting.

= 2.10 =
* Modified rate limiting to exclude non-subscriber logged-in users (e.g., administrators, editors) while applying limits to subscribers and non-logged-in users.
* Improved bot detection to identify suspicious bots using trusted User Agents.

= 2.9 =
* Added IP banning functionality for IPs exceeding block threshold.
* Added Banned IPs Log with timestamps and expiration times.
* Improved admin panel with ban threshold and duration settings.

= 2.6 =
* Added Cloudflare real IP detection using `CF-Connecting-IP` and `X-Forwarded-For` headers.
* Improved IP logging to use real client IPs for Cloudflare users.
* Added validation to ensure only Cloudflare IPs can use forwarded headers.

= 2.5 =
* Added logging of blocked IPs with timestamps, displayed in the admin panel.
* Added a "Clear Blocked IPs Log" button in the admin panel.
* Improved sanitization for blocked IP logs.

= 2.4 =
* Reintroduced static asset exclusion using `$_SERVER['REQUEST_URI']`.
* All text updated to English.
* Added cleanup of transients on plugin deactivation.

= 2.3 =
* Added alternative static asset exclusion using WordPress functions.
* Improved database cleanup on deactivation.

= 2.0 =
* Added admin panel for configuring rate limits and bot exclusions.
* Added bot exclusion functionality based on User Agents.
* Improved rate limiting logic.

= 1.0 =
* Initial release with basic rate limiting functionality.

== Upgrade Notice ==

= 2.14 =
This version adds automatic removal of duplicate IP ranges in the **Bot IP Ranges** field, simplifying IP range management. Update to ensure duplicate ranges are automatically handled on save.

= 2.13 =
This version adds a **Bot IP Ranges** field in the admin panel for easy management of trusted bot IPs. Update to simplify bot IP range updates every 6 months.

= 2.12 =
This version applies standard rate limiting to suspicious bots. Update to ensure consistent rate limiting behavior.

= 2.11 =
This version adds comprehensive bot IP ranges and suspicious bot detection. Update to enhance bot verification.

= 2.10 =
This version excludes non-subscriber logged-in users from rate limiting. Update to ensure only subscribers and non-logged-in users are rate-limited.

= 2.9 =
This version adds IP banning and Banned IPs Log. Update to enhance security with automatic bans.

= 2.6 =
This version adds Cloudflare real IP detection. Update to ensure accurate IP logging and rate limiting when using Cloudflare.

= 2.5 =
This version adds blocked IP logging and a clear option in the admin panel. Update to monitor blocked requests effectively.

== Other Notes ==
- **Cloudflare Compatibility**: Ensure Cloudflare is configured to pass `CF-Connecting-IP` headers for accurate IP detection. Check your Cloudflare dashboard if logged IPs are incorrect.
- **Bot IP Ranges**: Update the **Bot IP Ranges** field every 6 months (next update: March 2026) using official sources (e.g., Google, Bing, Yandex documentation). Duplicate ranges are automatically removed on save.
- **Performance**: For high-traffic sites, clear the Blocked IPs Log and Banned IPs Log regularly to prevent database growth.
- **Customization**: Contact the author for additional features like custom error pages, email notifications for suspicious bots, or advanced logging.
