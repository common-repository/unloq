<?php
/**
 * Plugin Name:       UNLOQ Authentication
 * Description:       Perform UNLOQ.io authentications with the click of a button
 * Version:           2.1.24
 * Author:            UNLOQ.io
 * Author URI:        https://unloq.io
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       unloq
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

define('UQ_PLUGIN', 'unloq');
define('UQ_VERSION', '2.1.24');
define('UQ_VENDORS', plugin_dir_url(__FILE__) . 'vendors');
define('UQ_VENDORS_DIR', plugin_dir_path(__FILE__) . 'vendors');
define('UQ_LOGIN_DIR', plugin_dir_path(__FILE__) . 'autoloader/login');

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
function load_wp_unloq_core() {
    require plugin_dir_path(__FILE__) . 'includes/class-core.php';
    add_action( 'admin_init', 'load_wp_unloq' );
}


function load_wp_unloq() {
    if(!is_admin()) return;
    if(!current_user_can('manage_options')) return;
    require plugin_dir_path(__FILE__) . 'includes/class-activator.php';
    $activator = new Wp_Unloq_Activator();
    $activator->activate();
}

add_action('plugins_loaded', 'load_wp_unloq_core', 1);
