<?php

/**
 * The file that defines the core plugin class
 *
 * A class definition that includes attributes and functions used across both the
 * public-facing side of the site and the admin area.
 *
 * @link       http://www.superwpheroes.io/
 * @since      1.0.0
 *
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/includes
 */

/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 * public-facing site hooks.
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/includes
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */
class Wp_Unloq
{

    /**
     * The loader that's responsible for maintaining and registering all hooks that power
     * the plugin.
     *
     * @since    1.0.0
     * @access   protected
     * @var      IFG_Loader $loader Maintains and registers all hooks for the plugin.
     */
    protected $loader;


    /**
     * @since    1.0.0
     * @access   public
     */
    public $utility;


    /**
     * Run the main processes
     *
     * @since 1.0.0
     * @return void
     */
    public function run()
    {
        $this->autoload();
        $this->loader = new Wp_Unloq_Loader;
        $this->utility = new Wp_Unloq_Utility;
        $plugin_i18n = new Wp_Unloq_i18n();

        $this->loader->add_action('init', $plugin_i18n, 'load_plugin_textdomain');
        $this->loader->run();
    }

    public function autoload()
    {
        require_once plugin_dir_path(dirname(__FILE__)) . 'autoloader/class-loader.php';
        require_once plugin_dir_path(dirname(__FILE__)) . 'autoloader/class-utility.php';
        require_once plugin_dir_path(dirname(__FILE__)) . 'includes/class-i18n.php';
        require_once plugin_dir_path(dirname(__FILE__)) . 'autoloader/class-rename-wplogin.php';
        require_once plugin_dir_path(dirname(__FILE__)) . 'autoloader/admin/class-admin.php';
        require_once plugin_dir_path(dirname(__FILE__)) . 'autoloader/login/class-login.php';
    }

    /**
     * Auto load all classes from a specific path.
     * @Deprecated
     * @since  1.0.0
     * @param  string $file_name
     */
    public function autoloader($filename = null)
    {
    }


}

$plugin = new Wp_Unloq;
$plugin->autoloader();
$plugin->run();
