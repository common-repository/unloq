=== UNLOQ Two Factor Authentication (2FA) ===
Contributors: unloqer
Tags: two-factor plugin, login, authenticator, two-factor authentication, google authenticator, login plugin, custom login url plugin, wp-login, wp-login-php, registration plugin, custom login, change login url, two-factor, two factor, 2 step authentication, 2 factor, 2FA, admin, ios, android, authentication, encryption, iphone, log in, login, mfa, mobile, multi factor, unloq, password, passwordless, phone, secure, security, smartphone, ssl, strong authentication, tfa, two factor authentication, two step, wp-admin, wp-login, authorization
Requires at least: 3.5
Requires PHP: 5.5
Tested up to: 4.9
Stable tag: trunk
License: MIT
License URI: http://opensource.org/licenses/MIT

60 seconds setup Two Factor Authentication (2FA). Featuring custom login URL, page customisation and 3 secure authentication methods.

== Description ==

We've designed the UNLOQ Two Factor Authentication Plugin so that anyone can install, configure and use it in a matter of seconds. We protect WordPress user accounts from credential-related risks while providing a customised authentication experience.
Some of the features included in our plugin are:

- 60 seconds setup

- Multiple login options

- Fully customisable

- Replaces the WP login and registration

- Custom login URL

- Shortcodes feature


<iframe src="https://www.youtube.com/embed/ua3c9RszfPE?rel=0&amp;showinfo=0" frameborder="0" allowfullscreen></iframe>

Full documentation available at: https://docs.unloq.io/plugins/wordpressv2

Two factor authentication protects you from password re-use, phishing and keylogger attacks. We are aware that the average user finds two factor authentication daunting, which is why we are leaving it up to you to choose the preferred authentication type.
You are now able to pick from:

- Password only authentication

- UNLOQ only

- Password and UNLOQ as second factor

When deciding to use UNLOQ as a sole or secondary login, you can choose from the following passwordless authentication methods:

- Push notification

- Time based one time password (TOTP)

- Email

No connection on your phone? We’ve got you covered. Click the menu button on the bottom right corner of the widget to see the other login options the application allows. Depending on your settings, these might come either as time based one time password (you’ll find the code by tapping on the desired application in the UNLOQ mobile app) or e-mail login. In case of a stolen phone you can deactivate your device at any moment, to protect your data.

We believe it’s about your application & your users. Make the authentication system your own: personalise the appearance of the login page and mobile app by adding your own background, website logo and colors.

Take the first step towards increasing the security of your WP website! For a step by step installation guide and answers to frequently asked questions, please visit us at https://docs.unloq.io/plugins/wordpressv2.

== Installation ==

### From your WordPress dashboard:

 1. Visit "Plugins > Add New"
 2. Search for "UNLOQ" and install the official plugin


### Manually via upload

 1. Download UNLOQ (https://github.com/UNLOQIO/wordpress-client/releases - latest release)
 2. Upload the "unloq.zip" into your plugins directory
 3. Install it

### Once activated
1. Enter your email address to receive the validation code. We recommend using the same e-mail address as your WordPress administrator.
2. Enter the validation code you received via email and go to the next step.
2.1. If you haven't already downloaded the mobile app, go ahead and get it from your application store of choice.
2.2. You will be shown a QR code to pair your mobile UNLOQ application to your WordPress site.

If you have any questions or installation issues, send us an e-mail at team@unloq.io . We will be happy to help you get started with UNLOQ.

== Screenshots ==
1. UNLOQ.io Login widget
2. UNLOQ.io Authentication request on your mobile device
3. UNLOQ.io Administrative interface

== Frequently Asked Questions ==

### Is UNLOQ really free?
The basic version is and will always be free. Your free account includes:
- unlimited applications, domains for up to 100 users per organisation
- e-mail and chat support
A premium version of the UNLOQ plugin will be available shortly.
For more information about features and pricing, please visit us at https://unloq.io/pricing.

### How do you keep the lights on?
UNLOQ authentication system is offered under a freemium model. The basic plan is free and it will always be free, but we also offer premium plans that adds additional security features, detailed analytics and support features for your customers. You may want to consider them when implementing UNLOQ.

### Can existing users on my WordPress site sign in with UNLOQ after I install the plugin?
Of course they can. As long as your users register on their UNLOQ mobile apps using the same e-mail address as their WordPress accounts, they can start using UNLOQ without any other configurations.

### How do I add users?
Depending on your setting to allow or not self registration (see in Wordpress > Settings > General) you could:
a. Let user self register. On their first login, a new user will be created with the default role set up in Settings > General;
b. Register the users manually in the Users section of the UNLOQ plugin.

### How does UNLOQ accommodate logins for WordPress users who do not have smartphones or don’t have internet access on their phone?
UNLOQ offers three ways to authenticate: UNLOQ push notification, time-based one time password and e-mail login. Users without internet connection or without a smartphone may use one of the other two options. You can choose what authentication methods you want to make available to your users from UNLOQ administrative panel.

### What should I do if my phone is lost, stolen, or if I switch to a new phone?
If you lose or change your phone, you can deactivate your account from your device and reactivate it on a new phone. To deactivate your phone, go to https://unloq.io/deactivate.

### How secure is UNLOQ authentication system?
UNLOQ’s security architecture is fully distributed, which means UNLOQ stores no user passwords on its servers. We only store your e-mail, name and profile picture (the last two are not required, but might enhance the user experience), but these cannot be used to login into any service by themselves. Only you, from your phone (or e-mail in case of e-mail login) can authorize the authentication request. All data on your phone are kept encrypted with AES-256-CBC and we use SSL on all communication channels.


### Language
For now, UNLOQ is only available in English.



== Changelog ==
= 2.1.24 =
Fixed an issue with authentication session start check
= 2.1.23 =
Removed Autocomplete
= 2.1.22 =
* Added the possibility to choose the organisation that will be used when creating the wordpress application
= 2.1.21 =
* Removed the option to delete users as it was causing confusion
= 2.1.20 =
* Fixed an issue with session_start()
= 2.1.19 =
* Fixed the login_redirect filter that is being applied to include the current user and the requested redirect url.
* Fixed an issue with e-mail login when initiating in UNLOQ-only mode from /unloq
= 2.1.18 =
* Fixed an issue for WordPress sites with PHP <= 5.3
= 2.1.17 =
* Fixed an issue where the application name was not correctly sent
= 2.1.16 =
* Login redirect filter now uses the default "login_redirect"
= 2.1.15 =
* Fixed setup bug with sites that do not have a name, to use a default site name
* The Multi-site SSO feature now auto-registers users that are not in the system, when the registration setting is enabled
= 2.1.14 =
* Fixed wp-login.php alias issue
= 2.1.13 =
* Added compatibility fixes with other auth plugins by delaying the plugin load until the "plugins-loaded" action
= 2.1.12 =
* All JavaScript assets now wait for the document ready event
= 2.1.11 =
* Added the possibility to completely reset all plugin credentials.
= 2.1.10 =
* Fixed an issue with .htaccess writable condition
= 2.1.9 =
* Fixed console CSS issues & added twitter button
= 2.1.8 =
* Added cache busting on plugin update
* Fixed an issue with email login on un-enrolled users
* Added security checks on admin data updates
= 2.1.7 =
* Fixed an issue with the prelogged cookie to be set to expire in 2 weeks
= 2.1.6 =
* Re-designed the /unloq path and functionality to better improve the user experience.
= 2.1.5 =
* Added compatibility check for WP-SpamShield plugin
= 2.1.4 =
* Fixed an issue with login redirect
= 2.1.3 =
* Fixed an issue with class autoloader
= 2.1.2 =
* Fixed an issue with admin menu role level
= 2.1.1 =
* Fixed upgrade compatibility from v1.x to 2.x
= 2.1.0 =
* Fixed issues with v1.x compatibility by adding the "SSO" Feature. You can now seamlessly enable v1.x login-style
* Added the "Autologin" setting for SSO-enabled sites
* Fixed upgrade process from 1.x to 2.x to correctly convert settings
= 2.0.9 =
* Fixed jQuery compatibility
= 2.0.8 =
* Fixed JavaScript error for the console page and login/register page
= 2.0.7 =
* Using local jQuery for consistency to avoid versioning errors.
= 2.0.6 =
* Fixed an issue with compatibility plugin
= 2.0.4 =
* Fixed an issue with compatibility plugin
= 2.0.3 =
* Minor fix on compatibility issue
= 2.0.2 =
* Minor fix on compatibility issue
= 2.0.1 =
* Minor fix on compatibility issue

= 2.0.0 =
* Complete plugin redesign to fully manage the login and register flow for WordPress users
* Plugin activation is now done without external pages.
* Customise your site's login page with colors and images
* Customise the in-app notification your users will receive
* Choose between the default WordPress login page and the UNLOQ login page
* Choose between Password Only, UNLOQ Only or Password & UNLOQ as second factor for your site's authentication mechanisms
* Backward-compatibility for previous versions of the plugin supported
* Manage your site's users directly from the plugin and invite your users to enable two-step authentication

= 1.5.19 =
* Fixed incorrect login URL redirects when used with plugins that perform i18n, and password reset/welcome email URL sending.

= 1.5.18 =
* On successful login, the global $user variable is updated with the user that just logged in, so that other plugins that depend on the global $user variable can read the latest user data.
 Specific issues were tested with "redirect-after-login" plugin.

= 1.5.17 =
* Custom login path is completely disabled while iTheme Security plugin is active. This is to avoid login issues and incompatibilities between plugins.

= 1.5.15 =
* Custom login path is now compatible with the iTheme Security plugin

= 1.5.14 =
* Fixed issues with PHP < 5.3 for class constants accessing

= 1.5.12 =
* Fixed an issue where all-in-one-wp-security-and-firewall plugin interferes with the login flow.

= 1.5.11 =
* Updated the authentication flow to prevent redirect loop

= 1.5.10 =
* The login.js file now handles the UNLOQ-only login method's token redirect without relying on the widget URL.

= 1.5.9 =
* The login.js file now automatically handles the token redirect without relying on the widget URL.

= 1.5.8 =
* Login JS script is now correctly enqueue and check for correct jQuery version to avoid theme conflicts

= 1.5.7 =
* Fixed static declaration to use array() constructor

= 1.5.6 =
* Fixed $_GET non-isset() checked variable

= 1.5.5 =
* util->getQuery() now works with $_GET in stead of $_SERVER

= 1.5.4 =
* Fixed $_POST variable checking to supress warnings
* Fixed register_hooks() function to be static

= 1.5.3 =
* Added the "Expos wp-admin/" functionality. If set to false, un-authenticated users that land on wp-admin/ will get a 404 in stead of the redirect to the login page. By default, this feature is disabled.

= 1.5.2 =
* Token parsing now takes place right after the "init" hook, and now looks directly into the server's querystring for the unloq_uauth key. Previously this was done using the "parse_request" hook, but quite a few plugins abuse of that hook and were stopping the UNLOQ authentication
* Updated the error message for expired tokens to include a bit more information

= 1.5.1 =
* Fixed UNLOQ-only enforcement on site administrators. It now applies only when the UNLOQ-only setting is active
* Fixed wp-admin/ 404 messages for single-site installations, for users that are not authenticated and apply the default functionality

= 1.5.0 =
* Fixed WooCommerce issues & other SSO plugins
* Added custom login path
* Added custom login logo and login page colors

= 1.1.3 =
* Updated plugin description, screenshots, FAQs

= 1.1.2 =
* Updated the setup steps text
* Do not restrict UNLOQ init only on wp-login.php and wp-register.php in order to load on all sites.
