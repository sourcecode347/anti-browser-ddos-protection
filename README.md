# Anti Browser DDoS Protection
Protects WordPress from DDoS with rate limiting, bot detection, blocking, Cloudflare support, logs, charts, and bot list export/import.

=== Anti Browser DDoS Protection ===

Author: SourceCode347

Contributors: sourcecode347

Plugin Name: Anti Browser DDoS Protection

Plugin URI: https://github.com/sourcecode347/anti-browser-ddos-protection

Donate link: https://buy.stripe.com/bIY5o70SSfam8Qo7ss

Tags: security, ddos-protection, rate-limiting, ip-blocking, bot-blocking

Requires at least: 5.0

Tested up to: 6.8

Stable tag: 2.22

Requires PHP: 8.3

License: GPLv2 or later

License URI: https://www.gnu.org/licenses/gpl-2.0.html

<img src="https://github.com/sourcecode347/anti-browser-ddos-protection/blob/main/Screenshot.png" style="width:100%;height:auto;"/>

<img src="https://github.com/sourcecode347/anti-browser-ddos-protection/blob/main/Screenshot2.png" style="width:100%;height:auto;"/>

<img src="https://github.com/sourcecode347/anti-browser-ddos-protection/blob/main/Screenshot3.png" style="width:100%;height:auto;"/>

== Description ==

The **Anti Browser DDoS Protection** plugin provides robust protection against denial-of-service (DoS) attacks on your WordPress site. It implements IP-based rate limiting, with configurable settings for subscribers, non-logged-in users, and verified bots, while excluding administrators and other non-subscriber roles. It features advanced bot detection to identify and limit suspicious bots, immediate blocking of malicious bots by User Agent, and supports Cloudflare for accurate client IP detection. Static assets (e.g., CSS, JS, images) are excluded to maintain site performance. An intuitive admin panel allows you to configure rate limits, bot exclusions, trusted bot IP ranges (with automatic duplicate removal), blocked bots by User Agent, log expiration settings, and view logs for blocked IPs, banned IPs, and high traffic bots with auto-refresh every 30 seconds, all with User Agent details and timestamps. You can export **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists to .txt files and import new entries to append to existing lists without duplicates. Daily bar charts for Blocked IPs, Banned IPs, and High Traffic Bots are displayed above the logs for quick visual insights.

**Key Features:**

- Rate limiting based on IP for subscribers and non-logged-in users, with configurable maximum requests and time window.
- Excludes non-subscriber logged-in users (e.g., administrators, editors) from rate limiting.
- Advanced bot detection to identify suspicious bots (bots using trusted User Agents but from unverified IPs).
- Suspicious bots are subject to the same rate limiting as regular users and logged with User Agent in the Blocked IPs Log.
- Immediate blocking of malicious bots by User Agent (e.g., MJ12bot, SemrushBot, DotBot by default) with customizable settings and logging.
- Configurable rate limiting for verified excluded bots (default: 100 requests per minute), with logging for bots exceeding this limit.
- High Traffic Excluded Bots Log to track verified bots with excessive requests, including IP, User Agent, and timestamp.
- Admin panel to configure maximum requests, time window, excluded bots, trusted bot IP ranges, blocked bots (User Agents), blocks before ban, ban duration, high traffic bot limits, and log expiration (days).
- Export **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists to .txt files for backup or transfer.
- Import .txt files for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** to append new entries to existing lists, with automatic duplicate removal.
- Automatic removal of duplicate IP ranges in the **Bot IP Ranges** field on save, keeping the first occurrence.
- Support for Cloudflare real IP detection using `CF-Connecting-IP` and `X-Forwarded-For` headers.
- Excludes static assets (CSS, JS, images, fonts, etc.) from rate limiting to optimize performance.
- Logs blocked IPs, banned IPs, and high traffic bots with IP, User Agent, and timestamps using the WordPress timezone, viewable in the admin panel with options to clear logs and auto-refresh every 30 seconds.
- Daily bar charts for Blocked IPs, Banned IPs, and High Traffic Bots displayed above the logs in the admin panel for visual statistics.
- Automatic log expiration (Blocked IPs, Banned IPs, High Traffic Bots) after a configurable number of days (default: 5 days), with hourly cleanup via WordPress Scheduler.
- All error messages and logs prefixed with "Anti Browser DDoS Protection: " for clarity.
- Donate link in the admin panel to support the project.
- Automatic cleanup of transients, blocked IPs, banned IPs, high traffic bots, blocked bots, bot IP ranges, and log expiration settings on plugin deactivation to prevent database bloat.

Ideal for WordPress sites seeking enhanced security against automated attacks, with seamless integration for Cloudflare users, advanced bot management, efficient log management, visual charts for statistics, and easy export/import for bot lists.

== Installation ==

1. Upload the `anti-ddos-protection` folder to the `/wp-content/plugins/` directory, or install the plugin directly through the WordPress plugins screen.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. **Disable any WordPress caching plugins** (e.g., WP Super Cache, W3 Total Cache) to ensure the Anti Browser DDoS Protection functions correctly, as caching plugins may bypass DDoS protection checks.
4. **Enable Browser Caching** using a service like Cloudflare and set DNS Records Proxy Status to Proxied.
   - Go Caching > Configuration : and set Standard type Caching and Configure Cloudflare Browser Cache TTL. (e.g., 8 days)
   - Set DNS Records Proxy Status to Proxied For More DDoS Security.
5. Navigate to **Settings > Anti DDoS** to configure the plugin settings:
   - Set the **Maximum Requests (Regular Users)** (e.g., 10 requests).
   - Set the **Time Window** in seconds (e.g., 60 seconds).
   - Set the **Maximum Requests (Excluded Bots)** (e.g., 100 requests per minute).
   - Set the **Log Expires (Days)** (e.g., 5 days) for automatic cleanup of logs.
   - Add **Excluded Bots** (User Agents, one per line, e.g., Googlebot, Bingbot). Export to .txt or import from .txt to append new entries (duplicates are removed).
   - Add **Bot IP Ranges** (trusted IP ranges in CIDR format, one per line, e.g., 66.249.64.0/19). Export to .txt or import from .txt to append new entries (duplicates are removed). Update every 6 months (next update: March 2026).
   - Add **Blocked Bots (User Agents)** (e.g., MJ12bot, SemrushBot, DotBot) to block malicious bots immediately. Export to .txt or import from .txt to append new entries (duplicates are removed).
   - Set **Blocks Before Ban** (e.g., 30 blocks) and **Ban Duration** (e.g., 24 hours).
6. Test the rate limiting by sending multiple requests (e.g., refreshing a page rapidly) using a subscriber account or non-logged-in IP to ensure blocking works.
7. Test suspicious bot detection by sending requests with a bot User Agent (e.g., Googlebot) from an unverified IP.
8. Test blocked bot detection by sending requests with a blocked User Agent (e.g., MJ12bot) to verify immediate blocking and logging.
9. Test high traffic bot logging by sending over 100 requests per minute from a verified bot IP (e.g., Googlebot from a trusted IP range).
10. Test export functionality by clicking "Export to TXT" for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** to download .txt files.
11. Test import functionality by uploading .txt files for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** to append new entries without duplicates.
12. Test log expiration by setting **Log Expires (Days)** to a low value (e.g., 1 day), generating log entries, and checking if they are automatically removed after the specified time.
13. Check the **Blocked IPs Log**, **Banned IPs Log**, and **High Traffic Excluded Bots Log** sections in the admin panel to view logs (including User Agent) with auto-refresh every 30 seconds and clear them if needed. Daily charts are displayed above the Blocked IPs Log for visual statistics.
14. Ensure the WordPress timezone (Settings > General > Timezone) is set correctly (e.g., `Europe/Athens` for Greece) for accurate timestamp display.

== Frequently Asked Questions ==

= Does this plugin work with Cloudflare? =
Yes, the plugin supports Cloudflare by using the `CF-Connecting-IP` header to detect the real client IP, ensuring accurate rate limiting and logging.

= Can I exclude specific bots from rate limiting? =
Yes, you can add User Agents (e.g., Googlebot, Bingbot) in the **Excluded Bots** field in the admin panel. Bots from trusted IP ranges (configured in **Bot IP Ranges**) are exempt from regular rate limiting but are subject to a separate limit (default: 100 requests per minute). You can export the list to .txt or import from .txt to append new entries.

= Can I block specific bots immediately? =
Yes, you can add User Agents (e.g., MJ12bot, SemrushBot, DotBot) in the **Blocked Bots (User Agents)** field in the admin panel. These bots are blocked immediately, logged in the Blocked IPs Log with their User Agent, and receive an "Anti Browser DDoS Protection: Blocked Bot Access Denied" message. You can export the list to .txt or import from .txt to append new entries.

= How are suspicious bots handled? =
Bots with trusted User Agents (e.g., Googlebot) but from unverified IPs are flagged as suspicious, logged in the Blocked IPs Log with their User Agent, and subjected to the same rate limiting as regular users (e.g., 10 requests per 60 seconds).

= How are high traffic excluded bots handled? =
Verified excluded bots (from trusted IP ranges) exceeding the configured limit (default: 100 requests per minute) are logged in the High Traffic Excluded Bots Log with their IP, User Agent, and timestamp. They are not blocked but monitored for high activity.

= Can I manage trusted bot IP ranges? =
Yes, you can configure trusted bot IP ranges in the **Bot IP Ranges** field in the admin panel (Settings > Anti DDoS). Enter ranges in CIDR format (e.g., 66.249.64.0/19), one per line. Duplicate ranges are automatically removed on save. You can export the list to .txt or import from .txt to append new entries. Update every 6 months.

= Are static assets like CSS and JS rate-limited? =
No, the plugin excludes common static assets (e.g., .css, .js, .jpg, .png) to prevent performance issues.

= Are logged-in users rate-limited? =
Only users with the `subscriber` role are rate-limited. Administrators, editors, and other non-subscriber roles are exempt.

= How do I view blocked, banned, or high traffic bot IPs? =
Go to **Settings > Anti DDoS** to see the **Blocked IPs Log**, **Banned IPs Log**, and **High Traffic Excluded Bots Log** tables, which list IPs, User Agents, timestamps, and ban expiration times with auto-refresh every 30 seconds. Daily bar charts are displayed above the Blocked IPs Log for visual insights. You can clear the logs using the provided buttons.

= How does log expiration work? =
The **Log Expires (Days)** setting (default: 5 days) automatically deletes Blocked IPs, Banned IPs, and High Traffic Bots logs older than the specified number of days. Cleanup runs hourly via the WordPress Scheduler.

= Can I export or import bot lists? =
Yes, you can export **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists to .txt files via links in the admin panel. You can also import .txt files to append new entries to these lists, with duplicates automatically removed on save.

= What happens when I deactivate the plugin? =
The plugin automatically deletes its transients, blocked IP logs, banned IP logs, high traffic bot logs, blocked bots, bot IP ranges, and log expiration settings from the database to prevent bloat.

== Screenshots ==

1. Admin panel under **Settings > Anti DDoS**, showing configuration options for Maximum Requests (Regular Users), Time Window, Maximum Requests (Excluded Bots), Log Expires (Days), Excluded Bots, Bot IP Ranges, Blocked Bots (User Agents), Blocks Before Ban, and Ban Duration, with Export to TXT and Import from TXT options for bot lists, and a Donate link above the settings.
2. Daily statistics charts for Blocked IPs, Banned IPs, and High Traffic Bots displayed above the logs in the admin panel.
3. Blocked IPs Log table, displaying IPs, User Agents, and timestamps with auto-refresh every 30 seconds and a Clear button.
4. Banned IPs Log table, showing IPs, User Agents, ban timestamps, and expiration times with auto-refresh every 30 seconds and a Clear button.
5. High Traffic Excluded Bots Log table, showing IPs, User Agents, and timestamps with auto-refresh every 30 seconds and a Clear button.
6. Example of the "Anti Browser DDoS Protection: Too many requests. Please slow down." error page when an IP exceeds the rate limit.
7. Example of the "Anti Browser DDoS Protection: Blocked Bot Access Denied" error page when a blocked bot is detected.
8. Example of the "Anti Browser DDoS Protection: Your IP is banned due to excessive requests." error page when an IP is banned.

== Changelog ==

= 2.22 =
* Fixed a bug that returned a critical site error to bots like facebookexternalhit when Cloudflare's Proxy Status was Proxied.

= 2.21 =
* Added plugin logo to the admin panel and plugin page for better branding.
* Fixed an issue where an admin notice was displayed repeatedly on every admin panel refresh.
* Added export functionality for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists to .txt files via links in the admin panel.
* Added import functionality for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists from .txt files, appending new entries to existing lists with automatic duplicate removal.

= 2.20 =
* Added daily bar charts for Blocked IPs, Banned IPs, and High Traffic Excluded Bots per day, displayed above the logs in the admin panel using Chart.js.
* Added **Log Expires (Days)** setting in the admin panel to configure automatic deletion of Blocked IPs, Banned IPs, and High Traffic Bots logs after a specified number of days (default: 5 days).
* Implemented hourly log cleanup via WordPress Scheduler to remove expired log entries.
* Added cleanup of **Log Expires (Days)** setting and scheduled cleanup event on plugin deactivation.

= 2.19 =
* Added auto-refresh of Blocked IPs, Banned IPs, and High Traffic Excluded Bots logs every 30 seconds in the admin panel using REST API endpoints.
* Improved log display with dynamic updates without manual page refresh.

= 2.18 =
* Added **Blocked Bots (User Agents)** setting in the admin panel to block malicious bots immediately, logs them to the Blocked IPs Log, and prefixes all error messages and logs with "Anti Browser DDoS Protection: ". Update to enhance bot blocking and improve message consistency.

= 2.17 =
* Added User Agent logging to Blocked IPs and Banned IPs logs for improved tracking and a Donate link above the settings in the admin panel to support the project. Update to enhance monitoring capabilities.

= 2.16 =
* Fixed timezone handling to use the WordPress timezone setting for accurate timestamp display and removes "Greece time" references from logs. Update to ensure timestamps reflect your site's configured timezone.

= 2.15 =
* Added configurable rate limiting for verified excluded bots, logs high traffic bots with IP, User Agent, and timestamp, and fixes timezone issues for accurate Greece time (Europe/Athens). Update to monitor high traffic bot activity and ensure correct timestamps.

= 2.14 =
* Added automatic removal of duplicate IP ranges in the **Bot IP Ranges** field, simplifying IP range management. Update to ensure duplicate ranges are automatically handled on save.

= 2.13 =
* Added **Bot IP Ranges** field in the admin panel for easy management of trusted bot IPs. Update to simplify bot IP range updates every 6 months.

= 2.12 =
* Updated suspicious bot handling to use standard rate limiting settings. Update to ensure consistent rate limiting behavior.

= 2.11 =
* Added comprehensive bot IP ranges and suspicious bot detection. Update to enhance bot verification.

= 2.10 =
* Modified rate limiting to exclude non-subscriber logged-in users from rate limiting. Update to ensure only subscribers and non-logged-in users are rate-limited.

= 2.9 =
* Added IP banning functionality for IPs exceeding block threshold.
* Added Banned IPs Log with timestamps and expiration times.
* Improved admin panel with ban threshold and duration settings.

= 2.6 =
* Added Cloudflare real IP detection using `CF-Connecting-IP` and `X-Forwarded-For` headers.
* Improved IP logging to use real client IPs for Cloudflare users.
* Added validation to ensure only Cloudflare IPs can use forwarded headers.

= 2.5 =
* Added IP logging of blocked IPs with timestamps, displayed in the admin panel.
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

== Bugs ==

Caching plugins such as WP Super Cache, W3 Total Cache, and others may bypass the DDoS protection provided by Anti Browser DDoS Protection, serving cached pages without triggering the plugin's checks for blocked bots, rate limiting, or banned IPs.
- **Solution**: Disable all WordPress caching plugins to ensure full DDoS protection. Instead, enable Browser Caching using a service like Cloudflare to improve performance without compromising security. 
   Enable standard type Caching and Configure Cloudflare Browser Cache TTL (e.g., 8 days) via **Caching > Configuration** in the Cloudflare dashboard.

== Upgrade Notice ==

= 2.22 =
This version fixed a bug that returned a critical site error to bots like facebookexternalhit.

= 2.21 =
This version adds a plugin logo for better branding and fixes an admin notice that appeared on every admin panel refresh. It also includes export and import functionality for **Excluded Bots**, **Bot IP Ranges**, and **Blocked Bots** lists, allowing you to back up lists to .txt files or append new entries from .txt files with automatic duplicate removal. Update to improve branding, resolve the admin notice issue, and manage bot lists more efficiently.

= 2.20 =
This version adds daily bar charts for Blocked IPs, Banned IPs, and High Traffic Excluded Bots in the admin panel, along with a **Log Expires (Days)** setting for automatic cleanup of logs after a configurable number of days (default: 5 days), with hourly cleanup via WordPress Scheduler. Update to gain visual insights and manage log retention efficiently.

= 2.19 =
This version adds auto-refresh of Blocked IPs, Banned IPs, and High Traffic Excluded Bots logs every 30 seconds in the admin panel. Update to enable dynamic log updates without manual page refresh.

= 2.18 =
This version adds a **Blocked Bots (User Agents)** setting to block malicious bots immediately, logs them to the Blocked IPs Log, and prefixes all error messages and logs with "Anti Browser DDoS Protection: ". Update to enhance bot blocking and improve message consistency.

= 2.17 =
This version adds User Agent logging to Blocked IPs and Banned IPs logs for improved tracking and a Donate link above the settings in the admin panel to support the project. Update to enhance monitoring capabilities.

= 2.16 =
This version fixes timezone handling to use the WordPress timezone setting for accurate timestamp display and removes "Greece time" references from logs. Update to ensure timestamps reflect your site's configured timezone.

= 2.15 =
This version adds configurable rate limiting for verified excluded bots, logs high traffic bots with IP, User Agent, and timestamp, and fixes timezone issues for accurate Greece time (Europe/Athens). Update to monitor high traffic bot activity and ensure correct timestamps.

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
- **Bot IP Ranges**: Update the **Bot IP Ranges** field every 6 months (next update: March 2026) using official sources (e.g., Google, Bing, Yandex documentation). Duplicate ranges are automatically removed on save. Export to .txt for backup or import from .txt to append new ranges.
- **Blocked Bots**: Add malicious bots to the **Blocked Bots (User Agents)** field (e.g., MJ12bot, SemrushBot, DotBot) to block them immediately. Blocked bots are logged with their IP and User Agent. Export to .txt for backup or import from .txt to append new entries.
- **Excluded Bots**: Add trusted bots (e.g., Googlebot, Bingbot) to the **Excluded Bots** field to exempt them from regular rate limiting (if from verified IPs). Export to .txt for backup or import from .txt to append new entries.
- **High Traffic Bots**: Verified bots exceeding the configured limit (default: 100 requests per minute) are logged for monitoring but not blocked. Check the High Traffic Excluded Bots Log regularly.
- **Log Expiration**: Set the **Log Expires (Days)** setting to control how long logs are retained (default: 5 days). Cleanup runs hourly via WordPress Scheduler. Logs older than the specified days are automatically deleted.
- **Timezone**: Set the WordPress timezone correctly (e.g., `Europe/Athens` for Greece) in Settings > General > Timezone to ensure accurate timestamp display in logs and charts.
- **Performance**: For high-traffic sites, clear the Blocked IPs Log, Banned IPs Log, and High Traffic Excluded Bots Log regularly, or set a lower **Log Expires (Days)** value to prevent database growth.
- **Customization**: Contact the author for additional features like custom error pages, email notifications for high traffic bots, or advanced logging.
- **Support the Project**: If you find this plugin useful, consider supporting its development via the [donation link](https://buy.stripe.com/bIY5o70SSfam8Qo7ss) in the admin panel or plugin page.
