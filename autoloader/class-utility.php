<?php
/**
 * This is a utility class
 *
 * @link       http://www.superwpheroes.io/
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/admin
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */

class Wp_Unloq_Utility
{

    const UNLOQ_FLASH_KEY = "wpunloq_sess";
    /**
     * Base url for UNLOQ.io REST Api
     *
     * @var string
     */
    protected $baseApiUrl = 'https://cms.unloq.io/v1';

    /**
     * Get wp options working on both single and multisite
     *
     * @since  1.0.0
     * @param  string $action e.g: get, update, delete
     * @param  sting $option the option name
     * @param  string $default the default value to return
     * @param  int $blog_id blog id if is necessary
     * @return bool
     */
    public function wp_option($action, $option, $default = '', $blog_id = null)
    {

        if (is_multisite()) {

            $blog_id = is_null($blog_id) ? get_current_blog_id() : $blog_id;

            $data = $this->multi_site($action, $option, $default, $blog_id);

        } else {

            $data = $this->single_site($action, $option, $default);
        }

        return $data;

    }

    /* Sets a flash message in the session */
    public static function flash($message = null, $type = 'error')
    {
        // IF no message, we retrieve all flashes.
        if ($message == null || $message === false) {
            if (!isset($_SESSION) || !isset($_SESSION[self::UNLOQ_FLASH_KEY])) {
                return array();
            }
            $tmp = $_SESSION[self::UNLOQ_FLASH_KEY];
            if ($message !== false) {
                unset($_SESSION[self::UNLOQ_FLASH_KEY]);
            }
            return $tmp;
        }
        if (!isset($_SESSION)) {
            return false;
        }
        $item = array('type' => $type, 'message' => $message);
        if (!isset($_SESSION[self::UNLOQ_FLASH_KEY])) {
            $_SESSION[self::UNLOQ_FLASH_KEY] = array();
        }
        array_push($_SESSION[self::UNLOQ_FLASH_KEY], $item);
        return true;
    }

    /*
     * Clears the UNLOQ flash for errors.
     * */
    public static function clearFlash()
    {
        if (isset($_SESSION[self::UNLOQ_FLASH_KEY])) {
            $_SESSION[self::UNLOQ_FLASH_KEY] = array();
        }
    }

    /*
     * Renders the given TPL file as html
     * The template path is relative to UQ_LOGIN_DIR
     * */
    public static function render($template, $vars = null)
    {
        if ($vars) {
            extract($vars);
        }
        ob_start();
        require(UQ_LOGIN_DIR . $template . '.tpl.php');
        echo ob_get_clean();
    }


    protected function single_site($action, $option, $default = false)
    {

        switch ($action) {

            case 'get';

                return get_option($option, $default);

                break;

            case 'update';

                $value = $default; // use default paramenter as value
                return update_option($option, $value);

                break;

            case 'delete';
                return delete_option($option);

                break;

        }
    }


    protected function multi_site($action, $option, $default = false, $blog_id)
    {

        switch ($action) {

            case 'get';

                return get_blog_option($blog_id, $option, $default);

                break;

            case 'update';

                $value = $default; // use default paramenter as value
                return update_blog_option($blog_id, $option, $value);

                break;

            case 'delete';

                return delete_blog_option($blog_id, $option);

                break;

        }
    }


    /**
     * Get wp transient working on both single and multisite
     *
     * @since  1.0.3
     * @param  string $action e.g: get, update, delete
     * @param  sting $transient the transient name
     * @param  string $default the default value to return
     * @param  int $blog_id blog id if is necessary
     * @return bool
     */
    public function wp_transient($action, $transient, $value, $expiration = 0)
    {

        if (is_multisite()) {

            $data = $this->multi_transient($action, $transient, $value, $expiration);

        } else {

            $data = $this->single_transient($action, $transient, $value, $expiration);
        }

        return $data;

    }


    /**
     * @since  1.0.3
     **/
    protected function single_transient($action, $transient, $value, $expiration = 0)
    {

        switch ($action) {

            case 'get';

                return get_transient($transient);

                break;

            case 'set';

                return set_transient($transient, $value, $expiration);

                break;

            case 'delete';
                return delete_transient($transient);

                break;

        }
    }


    /**
     * @since  1.0.3
     **/
    protected function multi_transient($action, $transient, $value, $expiration = 0)
    {

        switch ($action) {

            case 'get';

                return get_site_transient($transient);

                break;

            case 'set';

                return set_site_transient($transient, $value, $expiration);

                break;

            case 'delete';
                return delete_site_transient($transient);

                break;

        }
    }


    /**
     * Output the login url according to unloq slug
     *
     * @param  array $args
     * @since 1.0.4
     *
     * @return string
     */
    public function login_site_url($args = array())
    {

        $args = count($args) > 0 ? http_build_query($args) : '';
        $uq_slug = $this->rgar($this->wp_option('get', 'unloq_settings'), 'unloq_login_path', 'unloq');
        $permalink_structure = $this->wp_option('get', 'permalink_structure');
        $sign = $args == '' ? '' : ($permalink_structure == '' ? '&' : '?');
        $sign2 = $permalink_structure == '' ? '?' : '';
        $params = $sign . $args;
        $link = $permalink_structure == '' ? network_site_url($sign2 . $uq_slug . $params, 'login') : network_site_url($uq_slug . $params, 'login');
        return $link;
    }


    /**
     * Generate an activation key needed for reseting password
     *
     * @since 1.0.5
     * @param string $user_email
     * @return bool|string
     */
    public function generate_user_activation_key($user_email)
    {

        global $wpdb, $wp_hasher;

        $user = get_user_by('email', $user_email);
        $key = wp_generate_password(20, false);

        if ($user) {

            $user_login = $user->user_login;

            if (empty($wp_hasher)) {
                require_once ABSPATH . 'wp-includes/class-phpass.php';
                $wp_hasher = new PasswordHash(8, true);
            }

            $hashed = $wp_hasher->HashPassword($key);

            $wpdb->update(
                $wpdb->users,
                array(
                    'user_activation_key' => time() . ":" . $hashed
                ),
                array(
                    'user_login' => $user_login
                )
            );

            return $key;
        }

        return false;
    }


    /**
     * Send notification of passwoes set / reset
     *
     * @since 1.0.5
     * @param string $user_email
     * @param string $title
     * @param string $message
     * @return string
     */
    public function send_password_notification_email($user_email, $title, $message)
    {

        $user = get_user_by('email', $user_email);

        if ($user) {

            $user_login = $user->user_login;
            $user_email = $user->user_email;

            if (is_multisite()) {
                $blogname = $GLOBALS['current_site']->site_name;
            } else {
                $blogname = wp_specialchars_decode($this->wp_option('get', 'blogname'), ENT_QUOTES);
            }

            $title = sprintf(__('[%s] %s'), $blogname, $title);
            if ($message && !wp_mail($user_email, $title, $message)) {
                return __('Password reset e-mail could not be sent by your server.', 'unloq');
            }

        } else {
            return __('The requested user does not exist', 'unloq');
        }

        return true;
    }


    /**
     * Validate an url
     *
     * @since  1.0.0
     * @param  string $url
     * @return string
     */
    public function get_valid_url($url = '')
    {

        if (!empty($url)) {

            if (in_array(parse_url($url, PHP_URL_SCHEME), array('http', 'https'))) {

                if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
                    //valid url
                    return $url;
                } else {
                    //not valid url
                }
            } else {
                //no http or https
                return 'http://' . $url;
            }
        }
    }


    public function get_roles_from_settings($array)
    {

        if (is_array($array)) {
            $data = array();

            foreach ($array as $key => $val) {
                $data[$val->code] = $val->value;
            }

            return $data;
        }
    }


    public function null2empty($array)
    {

        if (!is_array($array)) {
            if (is_null($array)) {
                return '';
            }
        }

        foreach ($array as $key => $val) {
            if (is_null($val)) {
                $array[$key] = '';
            }
        }

        return $array;
    }


    /**
     * Get a specific property of an array without needing to check if that property exists.
     *
     * Provide a default value if you want to return a specific value if the property is not set.
     *
     * @since  1.0.0
     * @param array $array Array from which the property's value should be retrieved.
     * @param string $prop Name of the property to be retrieved.
     * @param string $default Optional. Value that should be returned if the property is not set or empty. Defaults to null.
     *
     * @return null|string|mixed The value
     */
    public function rgar($array, $prop, $default = null)
    {

        if (!is_array($array) && !(is_object($array) && $array instanceof ArrayAccess)) {
            return $default;
        }

        if (isset($array[$prop])) {
            $value = $array[$prop];
        } else {
            $value = '';
        }

        return empty($value) && $default !== null ? $default : $value;
    }


    /**
     * Gets a specific property within a multidimensional array.
     *
     * @since  Unknown
     * @access public
     *
     * @param array $array The array to search in.
     * @param string $name The name of the property to find.
     * @param string $default Optional. Value that should be returned if the property is not set or empty. Defaults to null.
     *
     * @return null|string|mixed The value
     */
    public function rgars($array, $name, $default = null)
    {

        if (!is_array($array) && !(is_object($array) && $array instanceof ArrayAccess)) {
            return $default;
        }

        $names = explode('/', $name);
        $val = $array;
        foreach ($names as $current_name) {
            $val = $this->rgar($val, $current_name, $default);
        }

        return $val;
    }

    /**
     * Retrieves information from UNLOQ Api, required for plugin upgrade
     *
     * @param $apiKey string
     * @param $action string
     *
     * @return boolean/string
     */
    public function get_migration_info($apiKey, $verb, $action, $body = null)
    {
        // we set the request parameters
        $url = $this->baseApiUrl . '/' . $action;
        $data = array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $apiKey,
                'Content-Type' => 'application/json',
            ));

        // execute the request depending on the HTTP verb
        switch ($verb) {
            case 'POST' :
                if (isset($body) && $body != null) {
                    $data['body'] = json_encode($body);
                }
                $response = wp_remote_post($url, $data);
                break;
            case 'GET' :
                $response = wp_remote_get($url, $data);
                break;
        }

        // process the response and return the correct data if the case
        if (!is_wp_error($response)) {
            if ((isset($response['body']))) {
                $body = json_decode($response['body']);

                if (isset($body->result))
                    return $body->result;
            }
        }

        return false;
    }

    /*
     * Checks if we have to disable the custom wp-login.php path
     * */
    public function isCustomLoginPathDisabled()
    {
        if (class_exists('ITSEC_Core')) return true;
        if (class_exists('WPS_Hide_Login')) return true;
        if (class_exists('c_ws_plugin__s2member_access_cap_times')) return true;
        return false;
    }

    /*
     * Returns the IP address of the request
     * */
    public function getIp()
    {
        $ip = $_SERVER['REMOTE_ADDR'];
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (isset($_SERVER['HTTP_X_REAL_IP']) && !empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        } elseif (isset($_SERVER['HTTP_CLIENT_IP']) && !empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        }
        return $ip;
    }
}
