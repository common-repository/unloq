<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * @link       http://www.superwpheroes.io/
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/autoloader/admin
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */

class Wp_Unloq_Admin
{

    /**
     * The loader that's responsible for maintaining and registering all hooks that power
     * the plugin.
     *
     * @since    1.0.0
     * @access   protected
     * @var      Wp_Unloq_Loader $loader Maintains and registers all hooks for the plugin.
     */
    protected $loader;


    /**
     * @since    1.0.0
     */
    public $utility;


    /**
     * @since    1.0.0
     */
    public static $API_url = 'https://cms.unloq.io/v1';

    /**
     * @since    1.0.0
     */
    public $settings;


    /**
     * @since    1.0.2
     */
    public $customise;


    /**
     * @since    1.0.0
     */
    private $api_key;


    /**
     * @since    1.0.0
     * @access   public
     */
    public static $instance = null;


    /**
     * Create a single instance of the class
     *
     * @since 1.0.0
     * @return object
     */
    public static function instance()
    {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }


    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     */
    public function __construct()
    {
        $this->loader = new Wp_Unloq_Loader;
        $this->utility = new Wp_Unloq_Utility;
        $this->settings = $this->utility->wp_option('get', 'unloq_settings') != '' ? $this->utility->wp_option('get', 'unloq_settings') : array();
        if (!isset($this->settings['sso'])) {
            $this->settings['sso'] = 'false';
        }
        if (!isset($this->settings['sso_autologin'])) {
            $this->settings['sso_autologin'] = 'false';
        }
        if (!isset($this->settings['premium_site'])) {
            $this->settings['premium_site'] = 'false';
        }
        $this->customise = $this->utility->wp_option('get', 'unloq_customise') != '' ? $this->utility->wp_option('get', 'unloq_customise') : array();

        $credentials = $this->utility->wp_option('get', 'unloq_credentials');
        $this->api_key = $this->utility->rgar($credentials, 'api_key');

        $this->loader->add_action('admin_enqueue_scripts', $this, 'enqueue_styles');
        $this->loader->add_action('admin_enqueue_scripts', $this, 'enqueue_scripts');
        $this->loader->add_action('admin_menu', $this, 'set_menu_page');
        $this->loader->add_action('init', $this, 'check_custom_login_path');
        $this->loader->add_action('admin_init', $this, 'check_login_rules');
        $this->loader->add_action('update_option_permalink_structure', $this, 'permalink_structure_update', 10, 2);
        $this->loader->add_action('unloq_update_login_slug', $this, 'rewrite_login_rules', 10, 2);

        // $this->loader->add_action( 'rest_url_prefix', $this, 'slug_rest_url_prefix', 999);
        // $this->loader->add_action( 'rest_api_init', $this, 'register_api_endpoints');

        $this->loader->add_action('wp_ajax_nopriv_uq_get_app_data', $this, 'process_uq_get_app_data');
        $this->loader->add_action('wp_ajax_uq_get_app_data', $this, 'process_uq_get_app_data');

        $this->loader->add_action('wp_ajax_nopriv_uq_get_users_per_page', $this, 'process_uq_get_users_per_page');
        $this->loader->add_action('wp_ajax_uq_get_users_per_page', $this, 'process_uq_get_users_per_page');

        $this->loader->add_action('wp_ajax_nopriv_uq_check_email', $this, 'process_uq_check_email');
        $this->loader->add_action('wp_ajax_uq_check_email', $this, 'process_uq_check_email');

        $this->loader->add_action('wp_ajax_nopriv_uq_verify_code', $this, 'process_uq_verify_code');
        $this->loader->add_action('wp_ajax_uq_verify_code', $this, 'process_uq_verify_code');

        $this->loader->add_action('wp_ajax_nopriv_uq_verify_organizations', $this, 'process_uq_verify_organizations');
        $this->loader->add_action('wp_ajax_uq_verify_organizations', $this, 'process_uq_verify_organizations');

        $this->loader->add_action('wp_ajax_nopriv_uq_reset_qr', $this, 'process_uq_reset_qr');
        $this->loader->add_action('wp_ajax_uq_reset_qr', $this, 'process_uq_reset_qr');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_settings', $this, 'process_uq_set_settings');
        $this->loader->add_action('wp_ajax_uq_set_settings', $this, 'process_uq_set_settings');
        $this->loader->add_action('wp_ajax_uq_set_sso', $this, 'process_uq_set_sso');
        $this->loader->add_action('wp_ajax_uq_set_sso_autologin', $this, 'process_uq_set_sso_autologin');
        $this->loader->add_action('wp_ajax_uq_activate_premium', $this, 'process_uq_activate_premium');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_authentication_methods', $this, 'process_uq_set_authentication_methods');
        $this->loader->add_action('wp_ajax_uq_set_authentication_methods', $this, 'process_uq_set_authentication_methods');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_authentication_roles', $this, 'process_uq_set_authentication_roles');
        $this->loader->add_action('wp_ajax_uq_set_authentication_roles', $this, 'process_uq_set_authentication_roles');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_authentication_page', $this, 'process_uq_set_authentication_page');
        $this->loader->add_action('wp_ajax_uq_set_authentication_page', $this, 'process_uq_set_authentication_page');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_organization', $this, 'process_uq_set_organization');
        $this->loader->add_action('wp_ajax_uq_set_organization', $this, 'process_uq_set_organization');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_customise_colors', $this, 'process_uq_set_customise_colors');
        $this->loader->add_action('wp_ajax_uq_set_customise_colors', $this, 'process_uq_set_customise_colors');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_customise_images', $this, 'process_uq_set_customise_images');
        $this->loader->add_action('wp_ajax_uq_set_customise_images', $this, 'process_uq_set_customise_images');

        $this->loader->add_action('wp_ajax_nopriv_uq_set_welcome_text', $this, 'process_uq_set_welcome_text');
        $this->loader->add_action('wp_ajax_uq_set_welcome_text', $this, 'process_uq_set_welcome_text');

        $this->loader->add_action('wp_ajax_nopriv_uq_create_user', $this, 'process_uq_create_user');
        $this->loader->add_action('wp_ajax_uq_create_user', $this, 'process_uq_create_user');

        $this->loader->add_action('wp_ajax_nopriv_uq_invite_user_profile', $this, 'process_uq_invite_user_profile');
        $this->loader->add_action('wp_ajax_uq_invite_user_profile', $this, 'process_uq_invite_user_profile');

        $this->loader->add_action('wp_ajax_nopriv_uq_deactivate_user_profile', $this, 'process_uq_deactivate_user_profile');
        $this->loader->add_action('wp_ajax_uq_deactivate_user_profile', $this, 'process_uq_deactivate_user_profile');

        $this->loader->add_action('wp_ajax_nopriv_uq_delete_user_profile', $this, 'process_uq_delete_user_profile');
        $this->loader->add_action('wp_ajax_uq_delete_user_profile', $this, 'process_uq_delete_user_profile');

        $this->loader->add_action('wp_ajax_nopriv_uq_remove_image', $this, 'process_uq_remove_image');
        $this->loader->add_action('wp_ajax_uq_remove_image', $this, 'process_uq_remove_image');

        $this->loader->add_action('wp_ajax_nopriv_uq_reset_plugin', $this, 'process_uq_reset_plugin');
        $this->loader->add_action('wp_ajax_uq_reset_plugin', $this, 'process_uq_reset_plugin');

        //run all hooks
        $this->loader->run();

        //send customise images to be uploaded
        $this->send_customise_image();

    }


    public function check_custom_login_path()
    {
        if ($this->utility->isCustomLoginPathDisabled()) {
            $this->settings['wp_login_path_disabled'] = 'true';
        } else {
            $this->settings['wp_login_path_disabled'] = 'false';
        }
    }

    /**
     * Register the stylesheets for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_styles()
    {

        if (isset($_GET['page']) && $_GET['page'] == 'unloq') {

            wp_enqueue_style('loader', UQ_VENDORS . '/ui/css/loader.css', array(), UQ_VERSION, 'all');
            wp_enqueue_style('account', UQ_VENDORS . '/ui/css/account.css', array(), UQ_VERSION, 'all');
            wp_enqueue_style('flexboxgrid', UQ_VENDORS . '/ui/css/flexboxgrid.min.css', array(), UQ_VERSION, 'all');
            wp_enqueue_style('admin', plugin_dir_url(__FILE__) . 'css/admin.css', array(), UQ_VERSION, 'all');
        }
    }

    /**
     * Register the JavaScript for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_scripts()
    {

        if (isset($_GET['page']) && $_GET['page'] == 'unloq') {
            wp_enqueue_script('account', UQ_VENDORS . '/ui/js/account.js', array(), UQ_VERSION, true);

            wp_localize_script('account', 'wpVars', array(
                'reactSrc' => UQ_VENDORS . '/ui/',
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'ajaxNonce' => wp_create_nonce('unloq_key')
            ));
        }

    }


    public function set_menu_page()
    {

        add_menu_page(
            __('UNLOQ', 'unloq'),
            __('UNLOQ'),
            'manage_options',
            'unloq',
            array($this, 'output_page'),
            plugins_url('/img/icon.png', __FILE__)
        );
    }

    public function output_page()
    {
        require_once UQ_VENDORS_DIR . '/ui/index.html';
    }


    public function forbidden_slugs()
    {
        $wp = new WP;
        return array_merge($wp->public_query_vars, $wp->private_query_vars);
    }


    /**
     * Get app data
     *
     * @since 1.0.2
     * @return json
     */
    public function process_uq_get_app_data()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $errors = false;
        wp_send_json(array(
            'errors' => $errors,
            'settings' => $this->get_settings(),
            'organisation' => $this->get_organization(),
            'customise' => $this->get_customise(),
            'users' => $this->get_users(),
        ));

    }


    /**
     * Add rewrite rules to redirect login slug on admin init
     *
     * @since 1.0.6
     * @return void
     */
    public function check_login_rules()
    {
        do_action('unloq_update_login_slug', '', false);
    }


    /**
     * Add rewrite rules to redirect login slug on permalink structure update
     *
     * @since 1.0.6
     * @param string $old_val
     * @param string $new_val
     * @return void
     */
    public function permalink_structure_update($old_val, $new_val)
    {
        do_action('unloq_update_login_slug', '', true);
    }


    /**
     * Add rewrite rules to redirect login slug
     *
     * @since 1.0.6
     *
     * @param string $slug
     * @param bool $update
     * @return void
     */
    public function rewrite_login_rules($slug, $update)
    {

        $file = realpath('../.htaccess');
        $base = str_replace($_SERVER['DOCUMENT_ROOT'], '', ABSPATH);
        $slug = $slug == '' ? $this->utility->rgar($this->settings, 'unloq_login_path', 'unloq') : $slug;
        $permalink_structure = $this->utility->wp_option('get', 'permalink_structure');

        if (file_exists($file)) {

            if (!is_writable($file)) {
                return;
            }

            $new = '# BEGIN Unloq
				<IfModule mod_rewrite.c>
				RewriteEngine On
				RewriteBase ' . $base . '
				RewriteRule ^index\.php$ - [L]
				RewriteRule ^([_0-9a-zA-Z-]+/)?' . $slug . '$ ?' . $slug . ' [R=301,L]
				RewriteCond %{REQUEST_FILENAME} !-f
				RewriteCond %{REQUEST_FILENAME} !-d
				RewriteRule . ' . $base . 'index.php [L]
				</IfModule>
				# END Unloq';

            $new = preg_replace('/\t+/', '', $new);
            $current = file_get_contents($file);

            if ($permalink_structure == '') {
                //it does not exits
                if (strpos($current, '# BEGIN Unloq') === false && strpos($current, '# END Unloq') === false) {
                    $content = $new;
                    $content .= $current;
                    file_put_contents($file, $content);
                } else {
                    if ($update === true) {
                        $rule_content = substr($current, strpos($current, '# BEGIN Unloq'), strpos($current, '# END Unloq') + 11);
                        $current = str_replace($rule_content, $new, $current);
                        file_put_contents($file, $current);
                    }
                }

            }

            if ($permalink_structure != '') {
                //it exists
                if (strpos($current, '# BEGIN Unloq') !== false && strpos($current, '# END Unloq') !== false) {
                    $rule_content = substr($current, strpos($current, '# BEGIN Unloq'), strpos($current, '# END Unloq') + 11);
                    $current = str_replace($rule_content, '', $current);
                    file_put_contents($file, $current);
                }
            }
        }
    }


    /**
     * Get settings
     *
     * @since 1.0.2
     * @return json
     */
    public function get_settings()
    {
        global $wp_roles;

        $errors = false;
        $result = '';

        if ($this->api_key == '') {
            return array(
                'errors' => __('The app does not have an api key, please set up the app.', 'unloq'),
                'result' => '',
            );
        }

        $remote = wp_remote_get(self::$API_url . '/settings', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $return = array();
                $result = $this->utility->null2empty($this->utility->rgar($body, 'result'));
                $return = $result;
                $auth_roles = array();

                if ($this->utility->rgar($this->settings, 'authentication_roles') == '') {
                    foreach ($wp_roles->get_names() as $key => $role) {
                        $auth_roles[$key] = 'password_only';
                    }
                    $return['authentication_roles'] = $auth_roles;
                }
                if ($this->utility->rgar($this->settings, 'authentication_roles') == '') {
                    $return['unloq_login_path'] = 'unloq';
                }
                if ($this->utility->rgar($this->settings, 'wp_login_active') == '') {
                    $return['wp_login_active'] = 'true';
                }
                if ($this->utility->rgar($this->settings, 'wp_login_path') == '') {
                    $return['wp_login_path'] = 'wp-login.php';
                }
                $return['wp_roles'] = $wp_roles->get_names();

                //merge with local settings
                $return = array_merge($this->settings, $return);

                $store_data = $this->utility->wp_option('update', 'unloq_settings', $return);
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        return array(
            'errors' => $errors,
            'result' => $return,
        );
    }


    /**
     * Get organization
     *
     * @since 1.0.2
     * @return json
     */
    public function get_organization()
    {

        $errors = false;
        $result = '';

        if ($this->api_key == '') {
            return array(
                'errors' => __('The app does not have an api key, please set up the app.', 'unloq'),
                'result' => '',
            );
        }

        $remote = wp_remote_get(self::$API_url . '/organization', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $result = $this->utility->null2empty($this->utility->rgar($body, 'result'));
                $result['view'] = true;
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        return array(
            'errors' => $errors,
            'result' => $result,
        );
    }


    /**
     * Get customise
     *
     * @since 1.0.2
     * @return json
     */
    public function get_customise()
    {

        $errors = false;
        $result = '';

        if ($this->api_key == '') {
            return array(
                'errors' => __('The app does not have an api key, please set up the app.', 'unloq'),
                'result' => '',
            );
        }

        $remote = wp_remote_get(self::$API_url . '/customize', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $result = $this->utility->rgar($body, 'result');
                $result['welcome_text'] = $this->utility->rgar($this->customise, 'welcome_text');

                $store_data = $this->utility->wp_option('update', 'unloq_customise', array_merge($this->customise, $result));
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        return array(
            'errors' => $errors,
            'result' => $result,
        );
    }


    /**
     * Get users
     *
     * @since 1.0.3
     * @return json
     */
    public function get_users($paged = 1)
    {

        global $wp_roles;

        $errors = false;
        $wp_users = array();
        $roles = array();
        $per_page = 10;
        $page_count = 0;
        $enrolled = false;

        if ($this->api_key == '') {
            return array(
                'errors' => __('The app does not have an api key, please set up the app.', 'unloq'),
                'result' => '',
            );
        }

        foreach ($wp_roles->get_names() as $key => $role) {
            $roles[$key] = $role;
        }

        $count = new WP_User_Query(array('count_total' => true));

        if ($count->get_total() > $per_page) {
            $page_count = ceil($count->get_total() / $per_page);
        }

        $users = get_users(array(
            'paged' => $paged,
            'number' => $per_page
        ));

        foreach ($users as $item) {

            $get_enrolled = $this->utility->wp_transient('get', 'uq_u' . $item->ID . '_enrolled', true);

            if ($get_enrolled == '') {

                //check the pair status
                $remote = wp_remote_get(self::$API_url . '/pair/check', array(
                    'headers' => array(
                        'Authorization' => 'Bearer ' . $this->api_key,
                        'Content-Type' => 'application/json',
                    ),
                    'body' => array(
                        'email' => $item->user_email
                    )
                ));

                if (!is_wp_error($remote)) {

                    $body = json_decode($remote['body'], true);

                    if (isset($body['error'])) {
                        $errors = $this->utility->rgars($body, 'error/message');
                    } else {
                        $enrolled = $this->utility->rgars($body, 'result/enrolled');
                        $enrolled = $enrolled === false ? 'false' : 'true';

                        //save pair status for 24 hours
                        $this->utility->wp_transient('set', 'uq_u' . $item->ID . '_enrolled', $enrolled, 60 * 60 * 24);
                    }

                } else {
                    $errors = __('[1017] An error occurred while trying to send the request.', 'unloq');
                }

            } else {
                $enrolled = $get_enrolled;
            }

            $wp_users[$item->ID] = array(
                'ID' => $item->ID,
                'user_login' => $item->user_login,
                'display_name' => $item->display_name,
                'role' => $item->roles[0],
                'email' => $item->user_email,
                'get_enrolled' => $get_enrolled,
                'status' => $enrolled == 'false' ? 'Inactive' : 'Active'
            );
        }

        return array(
            'errors' => $errors,
            'result' => array(
                'wp_users' => $wp_users,
                'wp_roles' => $roles,
                'meta' => array(
                    'current_page' => 1,
                    'page_count' => $page_count
                )
            ),
        );
    }


    /**
     * Get users per page
     *
     * @since 1.0.3
     * @return json
     */
    public function process_uq_get_users_per_page()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $paged = $this->utility->rgar($_POST, 'page');
        $data = $this->get_users($paged);
        wp_send_json($data);

    }

    /**
     * Completely remove all UNLOQ Plugin options, resetting it
     * to its initial state.
     */
    public function process_uq_reset_plugin()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $this->utility->wp_option('delete', 'unloq_credentials');
        $this->utility->wp_option('delete', 'unloq_settings');
        $this->utility->wp_option('delete', 'unloq_customise');
        $this->utility->wp_option('delete', 'wpunloq');
        $this->utility->wp_option('delete', 'unloq_custom_admin_url');
        $this->utility->wp_option('delete', 'unloq_login_path');
        wp_send_json(array(
            'errors' => false
        ));
    }


    /**
     * Check email address
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_check_email()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $errors = false;
        $c_user = wp_get_current_user();
        $email = $this->utility->rgar($_POST, 'email');
        if (!is_email($email)) {
            $errors = __('Please enter a valid email', 'unloq');
        }
        $applicationName = get_bloginfo('name');
        if (!isset($applicationName) || $applicationName == '') {
            $applicationName = 'WP Site';
        }
        if ($errors === false) {
            $remote = wp_remote_post(self::$API_url . '/connect', array(
                'headers' => array(
                    'Content-Type' => 'application/json',
                ),
                'body' => json_encode(array(
                    'url' => get_bloginfo('url'),
                    'application_name' => $applicationName,
                    'site_email' => $c_user->user_email,
                    'unloq_email' => $email,
                    'platform' => 'WORDPRESS',
                )),
            ));

            if (!is_wp_error($remote)) {

                $response = $this->utility->rgar($remote, 'response');
                $code = $this->utility->rgar($response, 'code');
                $message = $this->utility->rgar($response, 'message');
                $body = json_decode($remote['body'], true);

                if (isset($body['error'])) {
                    $errors = $this->utility->rgars($body, 'error/message');
                }

            } else {
                $errors = __('An error occurred while trying to send the request.', 'unloq');
            }
        }

        wp_send_json(array(
            'errors' => $errors,
            'remote' => get_bloginfo('url'),
        ));
    }

    /**
     * Returns the organizations that the user has access to
     *
     */
    public function process_uq_verify_organizations()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $c_user = wp_get_current_user();
        $code = $this->utility->rgar($_POST, 'code');
        $email = $this->utility->rgar($_POST, 'email');

        if (!is_email($email)) {
            $errors = __('Please enter a valid email', 'unloq');
        }
        $applicationName = get_bloginfo('name');
        if (!isset($applicationName) || $applicationName == '') {
            $applicationName = 'WP Site';
        }
        $remote = wp_remote_post(self::$API_url . '/verify/organizations', array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode(array(
                'url' => get_bloginfo('url'),
                'application_name' => $applicationName,
                'site_email' => $c_user->user_email,
                'unloq_email' => $email,
                'platform' => 'WORDPRESS',
                'verification_code' => $code,
            )),
        ));


        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);
            if (isset($body['error'])) {
                $errors = $this->utility->rgar($body['error'], 'message');
            } else {
                $result = $this->utility->rgar($body, 'result');
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors,
            'result' => $result,
        ));
    }

    /**
     * Verify the code sent on email
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_verify_code()
    {

        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $mobile_qr = '';
        $c_user = wp_get_current_user();
        $code = $this->utility->rgar($_POST, 'code');
        $email = $this->utility->rgar($_POST, 'email');
        $orgId = $this->utility->rgar($_POST, 'organization_id');

        if (!is_email($email)) {
            $errors = __('Please enter a valid email', 'unloq');
        }
        $applicationName = get_bloginfo('name');
        if (!isset($applicationName) || $applicationName == '') {
            $applicationName = 'WP Site';
        }
        $remote = wp_remote_post(self::$API_url . '/verify', array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode(array(
                'url' => get_bloginfo('url'),
                'application_name' => $applicationName,
                'site_email' => $c_user->user_email,
                'unloq_email' => $email,
                'platform' => 'WORDPRESS',
                'verification_code' => $code,
                'organization_id' => $orgId
            )),
        ));


        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgar($body['error'], 'message');
            } else {
                $result = $this->utility->rgar($body, 'result');
                $api_key = $this->utility->rgar($result, 'api_key');
                $app_id = $this->utility->rgar($result, 'application_id');
                $mobile_qr = $this->utility->rgar($result, 'mobile_qr', false);

                $store_data = $this->utility->wp_option('update', 'unloq_credentials', array(
                    'api_key' => $api_key,
                    'application_id' => $app_id
                ));
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors,
            'mobile_qr' => $mobile_qr,
            'result' => $result,
        ));
    }


    /**
     * Reset QR image
     *
     * @since 1.0.2
     * @return json
     */
    public function process_uq_reset_qr()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $qr_image = false;
        $user_email = $this->utility->rgar($_POST, 'user_email');

        $remote = wp_remote_post(self::$API_url . '/pair', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode(array(
                'email' => $user_email
            ))
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $qr_image = $this->utility->rgars($body, 'result/qr_url');
            }
        }

        wp_send_json(array(
            'errors' => $errors,
            'qr_image' => $qr_image,
        ));
    }


    /**
     * Save settings
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_set_settings()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $application_name = $this->utility->rgar($_POST, 'application_name', 'WP Site');
        $push_message = $this->utility->rgar($_POST, 'push_message');
        $authentication_message = $this->utility->rgar($_POST, 'authentication_message');
        $remote = wp_remote_post(self::$API_url . '/settings', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json'
            ),
            'body' => json_encode(array(
                'application_name' => $application_name,
                'push_message' => $push_message,
                'authentication_message' => $authentication_message
            ))
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);
            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $store_data = $this->utility->wp_option('update', 'unloq_settings', array_merge($this->settings, array(
                    'application_name' => $application_name,
                    'push_message' => $push_message,
                    'authentication_message' => $authentication_message
                )));
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors
        ));
    }

    /*
    * Remove images from the ocnsole
    */
    public function process_uq_remove_image()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $errors = false;
        $imageType = $this->utility->rgar($_POST, 'img_type', false);
        if (!$imageType) {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
            wp_send_json(array(
                'errors' => $errors
            ));
            return;
        }
        $payload = array(
            'type' => $imageType
        );
        if (isset($this->settings['login_widget_key'])) {
            $payload['widget_id'] = $this->settings['login_widget_key'];
        }
        $remote = wp_remote_post(self::$API_url . '/customize/image/remove', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json'
            ),
            'body' => json_encode($payload)
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);
            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            }
        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors
        ));
    }

    /*
     * Enables the premium features on this plugin
     * */
    public function process_uq_activate_premium()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $remote = wp_remote_post(self::$API_url . '/premium/activate', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json'
            ),
            'body' => json_encode(array())
        ));
        if (!is_wp_error($remote)) {
            $body = json_decode($remote['body'], true);
            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                if (isset($body['result']) && is_array($body['result']) && isset($body['result']['is_premium'])) {
                    $this->settings['premium_site'] = 'true';
                }
            }
        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }
        $store_data = $this->utility->wp_option('update', 'unloq_settings', $this->settings);
        wp_send_json(array(
            'errors' => $errors
        ));
    }

    /*
     * Enables or disables SSO features.
     * */
    public function process_uq_set_sso()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $sso = $this->utility->rgar($_POST, 'sso', null);
        if ($sso === "true" || $sso === "false") {
            $this->settings['sso'] = $sso;
        }
        $errors = false;
        if (!isset($this->settings['login_widget_key']) || $this->settings['login_widget_key'] == null) {
            $remote = wp_remote_post(self::$API_url . '/widget', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json'
                ),
                'body' => json_encode(array(
                    'type' => 'LOGIN',
                    'url' => $this->utility->login_site_url()
                ))
            ));
            if (!is_wp_error($remote)) {
                $body = json_decode($remote['body'], true);
                if (isset($body['error'])) {
                    $errors = $this->utility->rgars($body, 'error/message');
                } else {
                    if (isset($body['result']) && is_array($body['result']) && isset($body['result']['key'])) {
                        $widgetKey = $body['result']['key'];
                        $this->settings['login_widget_key'] = $widgetKey;
                    }
                }
            } else {
                $errors = __('An error occurred while trying to send the request.', 'unloq');
            }
        }
        $store_data = $this->utility->wp_option('update', 'unloq_settings', $this->settings);
        wp_send_json(array(
            'errors' => $errors
        ));
    }

    public function process_uq_set_sso_autologin()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;
        $errors = false;
        $autologin = $this->utility->rgar($_POST, 'autologin', null);
        $body = array(
            'authentication_methods' => array()
        );
        $clean = array();
        foreach ($this->settings['authentication_methods'] as $val) {
            if ($val !== 'AUTOLOGIN') {
                array_push($clean, $val);
            }
        }
        if ($autologin == 'true') {
            array_push($clean, 'AUTOLOGIN');
        }

        $body['authentication_methods'] = $clean;
        $remote = wp_remote_post(self::$API_url . '/settings', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json'
            ),
            'body' => json_encode($body)
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);
            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $this->settings['authentication_methods'] = $clean;
                $this->settings['sso_autologin'] = $autologin;
                $store_data = $this->utility->wp_option('update', 'unloq_settings', $this->settings);
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }
        wp_send_json(array(
            'errors' => $errors
        ));
    }


    /**
     * Save authentication page
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_set_authentication_page()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $unloq_login_path = $this->utility->rgar($_POST, 'unloq_login_path');
        if ($unloq_login_path === 'wp-login.php' || $unloq_login_path == '/wp-login.php') {
            return wp_send_json(array(
                'errors' => 'You cannot set this path to the UNLOQ login path.',
            ));
        }
        $wp_login_active = $this->utility->rgar($_POST, 'wp_login_active');
        $wp_login_path = $this->utility->rgar($_POST, 'wp_login_path') == 'wp-login.php' ? 'wp-login.php' : sanitize_title_with_dashes($this->utility->rgar($_POST, 'wp_login_path'));

        if ($wp_login_path == 'wp-login' || in_array($wp_login_path, $this->forbidden_slugs())) {
            $errors = sprintf(
                __('This path "%s" is not allowed, please choose another one!.', 'unloq'),
                $wp_login_path
            );
        }

        if ($errors === false) {
            $store_data = $this->utility->wp_option('update', 'unloq_settings', array_merge($this->settings, array(
                'unloq_login_path' => strtolower($unloq_login_path),
                'wp_login_active' => $wp_login_active,
                'wp_login_path' => strtolower($wp_login_path),
            )));
        }

        do_action('unloq_update_login_slug', strtolower($unloq_login_path), true);

        wp_send_json(array(
            'errors' => $errors,
        ));
    }


    /**
     * Save authentication metods
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_set_authentication_methods()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        parse_str($this->utility->rgar($_POST, 'authentication_methods'), $authentication_methods);

        $errors = false;
        $authType = null;
        if (isset($authentication_methods['authentication_type'])) {
            $authType = $authentication_methods['authentication_type'];
            if ($authType !== 'unloq_only' && $authType !== 'unloq_second_factor' && $authType !== 'password_only') {
                $errors = __('Please select a valid authentication type');
            }
        }
        $authentication_methods = $authentication_methods['authentication_methods'];
        if ($authentication_methods == '') {
            $errors = __('Please select at least one authentication method.', 'unloq');
        }
        if (isset($this->settings['sso_autologin']) && $this->settings['sso_autologin'] == 'true') {
            array_push($authentication_methods, 'AUTOLOGIN');
        }
        if ($errors === false) {
            $remote = wp_remote_post(self::$API_url . '/settings', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json'
                ),
                'body' => json_encode(array(
                    'authentication_methods' => $authentication_methods
                ))
            ));

            if (!is_wp_error($remote)) {

                $body = json_decode($remote['body'], true);

                if (isset($body['error'])) {
                    $errors = $this->utility->rgars($body, 'error/message');
                } else {
                    $this->settings['authentication_methods'] = $authentication_methods;
                    if ($authType) {
                        $this->settings['authentication_type'] = $authType;
                    }
                    $store_data = $this->utility->wp_option('update', 'unloq_settings', $this->settings);
                }

            } else {
                $errors = __('An error occurred while trying to send the request.', 'unloq');
            }
        }

        wp_send_json(array(
            'errors' => $errors
        ));
    }


    /**
     * Save authentication type by roles
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_set_authentication_roles()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        parse_str($this->utility->rgar($_POST, 'authentication_roles'), $authentication_roles);
        $authentication_type = $this->utility->rgar($_POST, 'authentication_type', false);
        $new_data = array();
        if ($authentication_type !== false) {
            $new_data['authentication_type'] = $authentication_type;
        }
        if (is_array($authentication_roles) && count($authentication_roles) > 0) {
            $new_data['authentication_roles'] = $authentication_roles;
        }
        $store_data = $this->utility->wp_option('update', 'unloq_settings', array_merge($this->settings, $new_data));

        wp_send_json(array(
            'errors' => $errors,
            'new_data' => $new_data,
        ));
    }


    /**
     * Save organization
     *
     * @since 1.0.0
     * @return json
     */
    public function process_uq_set_organization()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $organisation = $this->utility->rgar($_POST, 'organisation');
        $country = $this->utility->rgar($_POST, 'country');
        $city = $this->utility->rgar($_POST, 'city');
        $address = $this->utility->rgar($_POST, 'address');
        $vat_number = $this->utility->rgar($_POST, 'vat_number');


        $remote = wp_remote_post(self::$API_url . '/organization', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode(array(
                'name' => $organisation,
                'country' => $country,
                'city' => $city,
                'address' => $address,
                'vat' => $vat_number,
            ))
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $result = $this->utility->rgar($body, 'result');
                $result['view'] = true;
                wp_send_json($result);
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors
        ));
    }


    /**
     * Send image to the api endpoint in order to be uploaded
     *
     * @since 1.0.2
     */
    protected function send_customise_image()
    {
        if (isset($_FILES['asset']) && is_array($_FILES['asset'])) {

            $file = $_FILES['asset'];
            $errors = false;
            $img_url = false;
            $image_type = $this->utility->rgar($_POST, 'img_type');
            $match_types = array(
                'APPLICATION_ICON' => 'image_application_icon',
                'APPLICATION_LOGO' => 'image_application_logo',
                'WIDGET_ICON' => 'image_login_widget_icon',
                'WIDGET_BACKGROUND' => 'image_login_background_image',
            );
            $body = array(
                'image_type' => $image_type, // Values are: "APPLICATION_ICON", "APPLICATION_LOGO", "WIDGET_ICON", "WIDGET_BACKGROUND"
                'mime' => $file['type']
            );
            if (isset($this->settings['login_widget_key'])) {
                $body['widget_id'] = $this->settings['login_widget_key'];
            }
            $remote = wp_remote_post(self::$API_url . '/image/upload', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json',
                ),
                'body' => json_encode($body)
            ));

            if (!is_wp_error($remote)) {

                $body = json_decode($remote['body'], true);

                if (isset($body['error'])) {
                    $errors = $this->utility->rgars($body, 'error/message');
                } else {
                    $url = $this->utility->rgars($body, 'result/url');
                    $boundary = 'bB1oxKFmZiuhDcRI9lnXbPhj';

                    $payload = '';
                    $payload .= '--' . $boundary;
                    $payload .= "\r\n";
                    $payload .= 'Content-Disposition: form-data; name="asset"; filename="' . $file['name'] . '"' . "\r\n";
                    $payload .= 'Content-Type: ' . $file['type'] . "\r\n";
                    $payload .= "\r\n";
                    $payload .= file_get_contents($file['tmp_name']);
                    $payload .= "\r\n";
                    $payload .= '--' . $boundary . '--';

                    $remote2 = wp_remote_post($url, array(
                        'headers' => array(
                            'Authorization' => 'Bearer ' . $this->api_key,
                            'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
                        ),
                        'body' => $payload
                    ));

                    if (!is_wp_error($remote2)) {
                        $body = json_decode($remote2['body'], true);

                        if (isset($body['error'])) {
                            $errors = $this->utility->rgars($body, 'error/message');
                        } else {
                            $img_url = $this->utility->rgars($body, 'result/url');

                            $data = $this->customise;
                            $data[$match_types[$image_type]] = $img_url;

                            $this->utility->wp_option('update', 'unloq_customise', $data);
                        }
                    }
                }

            } else {
                $errors = __('An error occurred while trying to send the request.', 'unloq');
            }

            wp_send_json(array(
                'errors' => $errors,
                'img_url' => $img_url,
                'image_type' => $image_type,
            ));
        }

    }


    /**
     * Set customise colors
     *
     * @since 1.0.2
     * @return json
     */
    public function process_uq_set_customise_colors()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;

        parse_str($this->utility->rgar($_POST, 'payload'), $payload);
        if (isset($this->settings['login_widget_key'])) {
            $payload['widget_id'] = $this->settings['login_widget_key'];
        }
        $remote = wp_remote_post(self::$API_url . '/customize', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode($payload)
        ));

        if (!is_wp_error($remote)) {

            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                $errors = $this->utility->rgars($body, 'error/message');
            } else {
                $store_data = $this->utility->wp_option('update', 'unloq_customise', array_merge($this->customise, $payload));
            }

        } else {
            $errors = __('An error occurred while trying to send the request.', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors,
            'payload' => $payload,
        ));
    }


    /**
     * Set Welcome text
     *
     * @since 1.0.2
     * @return json
     */
    public function process_uq_set_welcome_text()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $text = $this->utility->rgar($_POST, 'text');

        $this->utility->wp_option('update', 'unloq_customise', array_merge($this->customise, array(
            'welcome_text' => $text
        )));

        wp_send_json(array(
            'errors' => $errors,
            'text' => $text,
        ));
    }


    /**
     * Create new user
     *
     * @since 1.0.3
     * @return json
     */
    public function process_uq_create_user()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        parse_str($this->utility->rgar($_POST, 'payload'), $payload);
        $password = $this->utility->rgar($payload, 'password', false);
        $invite = $this->utility->rgar($payload, 'invite', "true");
        if ($invite !== "true" || !$password) {
            $password = wp_generate_password($length = 12, $include_standard_special_chars = false);
        }
        $errors = false;
        $user_data = array(
            'user_login' => $payload['username'],
            'user_email' => $payload['email'],
            'user_pass' => $password,
            'first_name' => $payload['first_name'],
            'last_name' => $payload['last_name'],
        );

        if (!validate_username($payload['username'])) {
            $errors = __('This username is not valid because it uses illegal characters', 'unloq');
        }

        if (!is_email($payload['email'])) {
            $errors = __('Please enter a valid email', 'unloq');
        }

        if ($errors === false && username_exists($payload['username']) !== false) {
            $errors = __('This username already exists', 'unloq');
        }

        if ($errors === false && email_exists($payload['email']) !== false) {
            $errors = __('This email already exists', 'unloq');
        }


        if ($errors === false) {
            if ($this->utility->rgar($payload, 'type', false) !== false) {
                $user_data['role'] = strtolower($this->utility->rgar($payload, 'type'));
            }
            $user_id = wp_insert_user($user_data);

            if (!is_wp_error($user_id)) {

                if ($payload['invite'] == 'true') {

                    $remote = wp_remote_post(self::$API_url . '/invite', array(
                        'headers' => array(
                            'Authorization' => 'Bearer ' . $this->api_key,
                            'Content-Type' => 'application/json',
                        ),
                        'body' => json_encode(array(
                            'email' => $payload['email'],
                            'domain' => get_site_url()
                        ))
                    ));

                    if (!is_wp_error($remote)) {

                        $body = json_decode($remote['body'], true);

                        if (isset($body['error'])) {
                            $errors = $this->utility->rgars($body, 'error/message');
                        }

                    } else {
                        $errors = __('An error occurred while trying to send the request.', 'unloq');
                    }

                    //send user notification email
                    $username = $payload['username'];
                    $email = $payload['email'];
                    $key = $this->utility->generate_user_activation_key($email);
                    $link = $this->utility->login_site_url(array(
                        'action' => 'rp',
                        'key' => $key,
                        'login' => rawurlencode($username),
                    ));

                    $message = sprintf(__('Username: %s'), $username) . "\r\n\r\n";
                    $message .= __('To set your password, visit the following address:') . "\r\n\r\n";
                    $message .= '<' . $link . ">\r\n\r\n";
                    $message .= $this->utility->login_site_url() . "\r\n";

                    $message = apply_filters('retrieve_password_message', $message, $key);

                    $sent = $this->utility->send_password_notification_email($email, 'Your username and password info', $message);

                    if ($sent !== true) {
                        $errors = $sent;
                    }
                }
            } else {
                $errors = __('An error occurred while trying to add the new user.', 'unloq');
            }
        }

        wp_send_json(array(
            'errors' => $errors
        ));
    }


    /**
     * Invite user profile
     *
     * @since 1.0.3
     * @return json
     */
    public function process_uq_invite_user_profile()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $email = $this->utility->rgar($_POST, 'email');

        if (!is_email($email)) {
            $errors = __('Email is invalid!', 'unloq');
        }

        if ($errors === false) {
            $remote = wp_remote_post(self::$API_url . '/invite', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json',
                ),
                'body' => json_encode(array(
                    'email' => $email,
                    'domain' => get_site_url()
                ))
            ));

            if (!is_wp_error($remote)) {

                $body = json_decode($remote['body'], true);

                if (isset($body['error'])) {
                    $errors = $this->utility->rgars($body, 'error/message');
                }

            } else {
                $errors = __('An error occurred while trying to send the request.', 'unloq');
            }
        }

        wp_send_json(array(
            'errors' => $errors,
        ));

    }


    /**
     * Deactivate user profile
     *
     * @since 1.0.3
     * @return json
     */
    public function process_uq_deactivate_user_profile()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $email = $this->utility->rgar($_POST, 'email');
        $user = get_user_by('email', sanitize_email($email));

        if ($user) {

            $user_data = array(
                $user->ID => array(
                    'ID' => $user->ID,
                    'user_login' => $user->user_login,
                    'display_name' => $user->display_name,
                    'role' => $user->roles[0],
                    'email' => $user->user_email,
                    'status' => 'Inactive',
                )
            );

            //set enrollement status to false
            $this->utility->wp_transient('set', 'uq_u' . $user->ID . '_enrolled', 'false', 60 * 60 * 24);

            if ($errors === false) {
                $remote = wp_remote_post('https://api.unloq.io/v1/deactivate', array(
                    'headers' => array(
                        'Authorization' => 'Bearer ' . $this->api_key,
                        'Content-Type' => 'application/json',
                    ),
                    'body' => json_encode(array(
                        'email' => $email
                    ))
                ));

                if (!is_wp_error($remote)) {

                    $body = json_decode($remote['body'], true);

                    if (isset($body['error'])) {
                        $errors = $this->utility->rgars($body, 'error/message');
                    }

                } else {
                    $errors = __('An error occurred while trying to send the request.', 'unloq');
                }
            }
        } else {
            $errors = __('User data could not be retrieved!', 'unloq');
        }

        wp_send_json(array(
            'errors' => $errors,
            'user' => $user_data,
        ));

    }

    /**
     * Deletes a user
     *
     * @since 1.0.3
     * @return json
     */
    public function process_uq_delete_user_profile()
    {
        if (!current_user_can('manage_options') || !check_ajax_referer('unloq_key', 'security', false)) return;

        $errors = false;
        $email = $this->utility->rgar($_POST, 'email');
        $user = get_user_by('email', sanitize_email($email));

        if (!$user) {
            return wp_send_json(array(
                'errors' => 'The requested user does not exist'
            ));
        }
        $removed = wp_delete_user($user->ID);
        if (is_wp_error($removed)) {
            return wp_send_json(array(
                'errors' => $removed
            ));
        }
        wp_send_json(array(
            'errors' => false
        ));
    }


}

Wp_Unloq_Admin::instance();
