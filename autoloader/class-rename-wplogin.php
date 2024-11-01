<?php


class Wp_Unloq_Rename_WP_Login
{

    /**
     * @since    1.0.0
     */
    private $wp_login_php;

    /**
     * @since    1.0.0
     */
    public $utility;

    /**
     * @since    1.0.0
     */
    protected $settings;

    /**
     * @since    1.0.1
     */
    protected $permalink_structure;


    public function __construct($data = array())
    {

        $this->settings = $data;
        $this->utility = new Wp_Unloq_Utility;
        $this->permalink_structure = $this->utility->wp_option('get', 'permalink_structure');

        // add_action('wp_logout',array($this, 'redirect_on_logout'));
        add_action('init', array($this, 'check_logout_action'));

        //do nothing if we have `wp-login` or `wp-login.php` set as `wp_login_path`
        if ($this->utility->rgar($this->settings, 'wp_login_active', 'false') == 'true' &&
            ($this->utility->rgar($this->settings, 'wp_login_path') == 'wp-login' ||
                $this->utility->rgar($this->settings, 'wp_login_path') == 'wp-login.php')) {
            return;
        }
        add_action('wp_loaded', array($this, 'wp_loaded'));

        add_filter('site_url', array($this, 'site_url'), 10, 4);
        add_filter('network_site_url', array($this, 'network_site_url'), 10, 3);
        add_filter('wp_redirect', array($this, 'wp_redirect'), 10, 2);

        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);
        $this->plugins_loaded();
        // echo '<pre>'.print_r($this->settings, 1).'</pre>';
    }

    public function check_logout_action()
    {
        if ((isset($_GET['action']) && $_GET['action'] == 'logout') && isset($_GET['_wpnonce'])) {
            $current_user = wp_get_current_user();
            $user_id = $current_user->ID;
            $sessions = WP_Session_Tokens::get_instance($user_id);
            $sessions->destroy_all();
            wp_redirect($this->new_login_url());
            exit();
        }
    }


    // public function redirect_on_logout(){
    // 	// setcookie('wordpress_user_prelogged', null, strtotime('-1 day'), '/');
    // 	wp_redirect( home_url($this->utility->rgar($this->settings, 'unloq_login_path')) );
    // 	exit();
    // }


    private function use_trailing_slashes()
    {
        return '/' === substr($this->permalink_structure, -1, 1);
    }


    private function user_trailingslashit($string)
    {
        return $this->use_trailing_slashes() ? trailingslashit($string) : untrailingslashit($string);
    }

    private function wp_template_loader()
    {
        global $pagenow;

        $pagenow = 'index.php';

        if (!defined('WP_USE_THEMES')) {
            define('WP_USE_THEMES', true);
        }

        wp();

        if ($_SERVER['REQUEST_URI'] === $this->user_trailingslashit(str_repeat('-/', 10))) {
            $_SERVER['REQUEST_URI'] = $this->user_trailingslashit('/wp-login-php/');
        }

        require_once(ABSPATH . WPINC . '/template-loader.php');

        die;
    }


    private function new_login_slug()
    {
        if ($this->utility->rgar($this->settings, 'wp_login_active', 'false') == 'true') {
            return $this->utility->rgar($this->settings, 'wp_login_path');
        } else {
            return $this->utility->rgar($this->settings, 'unloq_login_path', 'unloq');
        }
    }

    public function new_login_url($scheme = null)
    {
        $slug = $this->new_login_slug();
        if ($slug === 'wp-login.php') {
            return wp_login_url();
        }
        if ($this->permalink_structure) {
            return $this->user_trailingslashit(home_url('/', $scheme) . $this->new_login_slug());
        } else {
            return home_url('/', $scheme) . '?' . $this->new_login_slug();
        }
    }


    public function plugins_loaded()
    {
        global $pagenow;

        if (
            !is_multisite() && (
                strpos($_SERVER['REQUEST_URI'], 'wp-signup') !== false ||
                strpos($_SERVER['REQUEST_URI'], 'wp-activate') !== false
            )
        ) {
            wp_die(__('This feature is not enabled.', 'rename-wp-login'));
        }

        $request = parse_url($_SERVER['REQUEST_URI']);
        $wp_login_active = $this->utility->rgar($this->settings, 'wp_login_active');

        if ((
                strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false ||
                untrailingslashit($request['path']) === site_url('wp-login', 'relative')
            ) &&
            !is_admin()
        ) {
            $this->wp_login_php = true;
            $_SERVER['REQUEST_URI'] = $this->user_trailingslashit('/' . str_repeat('-/', 10));
            $pagenow = 'index.php';
        } elseif (
            untrailingslashit($request['path']) === home_url($this->new_login_slug(), 'relative') || (
                !$this->permalink_structure &&
                isset($_GET[$this->new_login_slug()]) &&
                empty($_GET[$this->new_login_slug()])
            )) {
            if ($wp_login_active == 'true') {
                $pagenow = 'wp-login.php';
            } else {
                $pagenow = 'index.php';
            }
        }
    }


    public function wp_loaded()
    {
        global $pagenow;

        if (is_admin() && !is_user_logged_in() && !defined('DOING_AJAX')) {
            wp_die(__('You must log in to access the admin area.', 'rename-wp-login'));
        }

        $request = parse_url($_SERVER['REQUEST_URI']);

        if (
            $pagenow === 'wp-login.php' &&
            $request['path'] !== $this->user_trailingslashit($request['path']) &&
            $this->permalink_structure
        ) {
            wp_safe_redirect($this->user_trailingslashit($this->new_login_url()) . (!empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : ''));
            die;
        } elseif ($this->wp_login_php) {
            if (
                ($referer = wp_get_referer()) &&
                strpos($referer, 'wp-activate.php') !== false &&
                ($referer = parse_url($referer)) &&
                !empty($referer['query'])
            ) {
                parse_str($referer['query'], $referer);

                if (
                    !empty($referer['key']) &&
                    ($result = wpmu_activate_signup($referer['key'])) &&
                    is_wp_error($result) && (
                        $result->get_error_code() === 'already_active' ||
                        $result->get_error_code() === 'blog_taken'
                    )) {
                    wp_safe_redirect($this->new_login_url() . (!empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : ''));
                    die;
                }
            }

            $this->wp_template_loader();
        } elseif ($pagenow === 'wp-login.php') {
            global $error, $interim_login, $action, $user_login;

            @require_once ABSPATH . 'wp-login.php';

            die;
        }
    }

    public function site_url($url, $path, $scheme, $blog_id)
    {
        return $this->filter_wp_login_php($url, $scheme);
    }

    public function network_site_url($url, $path, $scheme)
    {
        return $this->filter_wp_login_php($url, $scheme);
    }

    public function wp_redirect($location, $status)
    {
        return $this->filter_wp_login_php($location);
    }

    public function filter_wp_login_php($url, $scheme = null)
    {
        if (strpos($url, 'wp-login.php') !== false) {
            if (is_ssl()) {
                $scheme = 'https';
            }

            $args = explode('?', $url);

            if (isset($args[1])) {
                parse_str($args[1], $args);
                $url = add_query_arg($args, $this->new_login_url($scheme));
            } else {
                $url = $this->new_login_url($scheme);
            }
        }
        return $url;
    }

}