<?php

/**
 * Functionality of the login widget.
 *
 * @link       http://www.superwpheroes.io/
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/autoloader
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */
class Wp_Unloq_Login
{

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
        //run only in front-end

        $this->settings = $this->utility->wp_option('get', 'unloq_settings') != '' ? $this->utility->wp_option('get', 'unloq_settings') : false;
        if (!isset($this->settings['sso'])) {
            $this->settings['sso'] = 'false';
        }
        if (!isset($this->settings['sso_autologin'])) {
            $this->settings['sso_autologin'] = 'false';
        }
        if (!isset($this->settings['premium_site'])) {
            $this->settings['premium_site'] = 'false';
        }
        $credentials = $this->utility->wp_option('get', 'unloq_credentials') != '' ? $this->utility->wp_option('get', 'unloq_credentials') : false;
        $this->api_key = $this->utility->rgar($credentials, 'api_key');

        $this->customise = $this->utility->wp_option('get', 'unloq_customise') != '' ? $this->utility->wp_option('get', 'unloq_customise') : array();

        if ($this->settings === false || $credentials === false) {
            return;
        }
        if (!isset($this->settings['login_widget_key']) && isset($credentials['widget_key'])) {
            $this->settings['login_widget_key'] = $credentials['widget_key'];
            $this->settings['sso'] = 'true';
            $this->utility->wp_option('update', 'unloq_settings', $this->settings);
        }
        add_shortcode('UNLOQ-authenticate', array($this, 'authenticate_widget_shortcode'));
        add_shortcode('UNLOQ-register', array($this, 'register_widget_shortcode'));
        add_action('init', array($this, "uauth_token_login"), 0);
        new Wp_Unloq_Rename_WP_Login($this->settings);

        $this->loader->add_action('wp_enqueue_scripts', $this, 'enqueue_styles');
        $this->loader->add_action('wp_enqueue_scripts', $this, 'enqueue_scripts');

        $this->loader->add_action('init', $this, 'custom_rewrite_rule', 10, 0);
        //$this->loader->add_action('init', $this, 'collect_login_token');

        $this->loader->add_action('query_vars', $this, 'add_custom_vars', 0, 1);
        $this->loader->add_action('parse_request', $this, 'do_parse_request');


        /* 2.2 Login form */
        $this->loader->add_action('wp_ajax_nopriv_uq_login_identity', $this, 'process_uq_login_identity');
        $this->loader->add_action('wp_ajax_uq_login_identity', $this, 'process_uq_login_identity');

        $this->loader->add_action('wp_ajax_nopriv_uq_login_step', $this, 'process_uq_login_step');
        $this->loader->add_action('wp_ajax_uq_login_step', $this, 'process_uq_login_step');

        $this->loader->add_action('wp_ajax_nopriv_uq_login_enrolled', $this, 'process_uq_login_enrolled');
        $this->loader->add_action('wp_ajax_uq_login_enrolled', $this, 'process_uq_login_enrolled');

        $this->loader->add_action('wp_ajax_nopriv_uq_login_reset_send', $this, 'process_uq_login_reset_send');
        $this->loader->add_action('wp_ajax_uq_login_reset_send', $this, 'process_uq_login_reset_send');

        $this->loader->add_action('wp_ajax_nopriv_uq_login_reset', $this, 'process_uq_login_reset');
        $this->loader->add_action('wp_ajax_uq_login_reset', $this, 'process_uq_login_reset');

        $this->loader->add_action('wp_ajax_nopriv_uq_login_forget', $this, 'process_uq_login_forget');
        $this->loader->add_action('wp_ajax_uq_login_forget', $this, 'process_uq_login_forget');

        /* 2.2 Register form */
        if ($this->utility->wp_option('get', 'users_can_register') == '1') {
            $this->loader->add_action('wp_ajax_nopriv_uq_register_step', $this, 'process_uq_register_step');
            $this->loader->add_action('wp_ajax_uq_register_step', $this, 'process_uq_register_step');
        }

        // ForSSO login form.
        if (isset($this->settings['login_widget_key']) && strlen($this->settings['login_widget_key'])) {
            $this->sso_init();
        }
        $this->loader->run();

    }

    /**
     * Returns information about the given user, his authentication methods
     * and pair status.
     */
    public function get_login_data($user, $checkPair = true)
    {
        $props = array(
            'name' => $user->display_name,
            'email' => $user->user_email
        );
        $image = get_user_meta($user->ID, 'unloq_user_image', true);
        if (isset($image) && is_string($image)) {
            $props['image'] = $image;
        }
        if (!isset($props['name']) || !$props['name']) {
            $props['name'] = $user->user_login;
        }
        $user_roles = (array)$user->roles;
        $userRole = false;
        foreach ($user_roles as $role) {
            $uRole = $this->get_auth_by_role($role);
            if ($uRole !== false) {
                $userRole = $uRole;
                break;
            }
        }
        $data = array(
            'user' => $props,
            'authentication_type' => 'password_only',
            'authentication_methods' => array()
        );
        if ($this->settings['premium_site'] === 'true' && $userRole) {
            $data['authentication_type'] = $userRole;
        } else {
            if (isset($this->settings['authentication_type'])) {
                $data['authentication_type'] = $this->settings['authentication_type'];
            }
        }
        // Check if the user is enrolled.
        $data['user']['enrolled'] = false;
        if ($data['authentication_type'] !== 'password_only' && $checkPair == true) {
            $remote = wp_remote_get(self::$API_url . '/pair/check', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json',
                ),
                'body' => array(
                    'email' => $props['email']
                )
            ));
            if (!is_wp_error($remote)) {
                $body = json_decode($remote['body'], true);
                if (!isset($body['error'])) {
                    $data['user']['enrolled'] = $this->utility->rgars($body, 'result/enrolled', false);
                }
            }
        }
        // Set our methods.
        if (in_array('UNLOQ', $this->settings['authentication_methods'])) {
            array_push($data['authentication_methods'], 'UNLOQ');
        }
        if (in_array('OTP', $this->settings['authentication_methods'])) {
            array_push($data['authentication_methods'], 'OTP');
        }
        if ($data['authentication_type'] === 'unloq_only' && in_array('EMAIL', $this->settings['authentication_methods'])) {
            array_push($data['authentication_methods'], 'EMAIL');
        }
        return $data;
    }

    /**
     * Returns the current settings of the plugin
     * and the user data (if any) associated to the current session.
     */
    public function get_page_data($user = false)
    {
        $data = array(
            'reactSrc' => UQ_VENDORS . '/ui/',
            'user_profile' => admin_url('index.php'),
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'ajaxNonce' => wp_create_nonce('unloq_key'),
            'user' => null,
            'page' => 'login',
            'errors' => false,
            'login_url' => $this->utility->login_site_url()
        );
        if ($this->utility->wp_option('get', 'users_can_register') == '1') {
            $data['register_url'] = $this->utility->login_site_url(array('action' => 'register'));
        }
        /* Check if we have a reset password */
        if (isset($_GET['action']) && $_GET['action'] === 'rp'
            && isset($_GET['key']) && strlen($_GET['key']) > 0
            && isset($_GET['login']) && strlen($_GET['login']) > 0) {
            $login = $_GET['login'];
            $key = $_GET['key'];
            $errors = false;
            $user = get_user_by('login', $login);
            if ($user) {
                $check_key = check_password_reset_key($key, $user->user_login);
                $data['page'] = 'reset';
                if (is_wp_error($check_key)) {
                    $errors = 'Invalid reset password token.';
                }
            } else {
                $errors = "User does not exist";
            }
            $data['errors'] = $errors;
        }
        if (!isset($user) || !$user) {
            if (isset($_COOKIE['wp_unloq_prelogged'])) {
                $userName = $_COOKIE['wp_unloq_prelogged'];
                $user = get_user_by('login', sanitize_text_field($userName));
                if (!$user) {
                    $this->clear_prelogged();
                } else {
                    if (isset($_SESSION['unloq_pwd_checked.' . $user->user_login])) {
                        unset($_SESSION['unloq_pwd_checked.' . $user->user_login]);
                    }
                    if (isset($_SESSION['unloq_enroll_checked'])) {
                        unset($_SESSION['unloq_enroll_checked']);
                    }
                }
            }
        }
        if (isset($user) && $user) {
            $data['user'] = $this->get_login_data($user);
        }
        return $data;
    }

    /**
     * Checks the user identity information given an e-mail address.
     * It will do so by querying either by email or username.
     */
    private function check_identity()
    {
        $userName = $this->utility->rgar($_POST, 'email', false);
        if (!$userName) {
            throw new Error("Please enter your e-mail address");
        }
        if (strpos($userName, '@') === false) {
            $loginType = 'login';
            $loginValue = sanitize_text_field($userName);
        } else {
            $loginType = 'email';
            $loginValue = sanitize_email($userName);
        }
        $user = get_user_by($loginType, $loginValue);
        if (!$user) {
            throw new Error("The requested user does not exist");
        }
        return $user;
    }

    /**
     * Starts the user session, performing cleanup as well.
     */
    private function start_session($user, $asJson = true, $unloqUser = null)
    {
        parse_str($this->utility->rgar($_POST, 'query'), $query);
        $redirect_to = $this->utility->rgar($query, 'redirect_to', admin_url('index.php'));
        $requested_redirect_to = isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '';
        $redirectTo = apply_filters('login_redirect', $redirect_to, $requested_redirect_to, $user);
        if (isset($_SESSION['unloq_enroll_checked'])) {
            unset($_SESSION['unloq_enroll_checked']);
        }
        if (isset($_SESSION['unloq_pwd_checked.' . $user->user_login])) {
            unset($_SESSION['unloq_pwd_checked.' . $user->user_login]);
        }
        if (isset($unloqUser) && $unloqUser != null) {
            // Save user's meta information
            if (isset($unloqUser['image'])) {
                update_user_meta($user->ID, 'unloq_user_image', $unloqUser['image']);
            }
        }
        $secure_cookie = is_ssl();
        if (FORCE_SSL_ADMIN) {
            $secure_cookie = true;
            force_ssl_admin(true);
        }
        $this->set_prelogged($user->user_login, $secure_cookie);
        wp_set_auth_cookie($user->ID, false, $secure_cookie);
        wp_set_current_user($user->ID, $user->user_login);
        if ($asJson) {
            return wp_send_json(array(
                'errors' => false,
                'redirect_url' => $redirectTo
            ));
        }
    }

    /**
     * Performing the Registration step
     * DATA:
     *  - username
     *  - email
     *  - password
     *
     */
    public function process_uq_register_step()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        $errors = false;
        $username = $this->utility->rgar($_POST, 'username');
        $email = $this->utility->rgar($_POST, 'email');
        $random_password = wp_generate_password($length = 12, $include_standard_special_chars = false);
        $user_data = array(
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => $random_password,
        );

        if (!validate_username($username)) {
            return wp_send_json(array(
                'errors' => __('This username is not valid', 'unloq')
            ));
        }

        if (!is_email($email)) {
            return wp_send_json(array(
                'errors' => __('Please enter a valid e-mail address', 'unloq')
            ));
        }

        if ($errors === false && username_exists($username) !== false) {
            return wp_send_json(array(
                'errors' => __('This username is unavailable', 'unloq')
            ));
        }
        if (email_exists($email) !== false) {
            return wp_send_json(array(
                'errors' => __('This e-mail address is unavailable', 'unloq')
            ));
        }
        // Create the user
        $user_id = wp_insert_user($user_data);
        if (is_wp_error($user_id)) {
            return wp_send_json(array(
                'errors' => __('An error occurred while creating user', 'unloq')
            ));
        }
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
            return wp_send_json(array(
                'errors' => $sent
            ));
        }
        return wp_send_json(array(
            'errors' => false
        ));
    }

    /**
     * Perform the "Continue" functionality
     * Data:
     *  - email=required
     */
    public function process_uq_login_identity()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        try {
            $user = $this->check_identity();
        } catch (Exception $e) {
            return wp_send_json(array(
                'errors' => $e->getMessage()
            ));
        }
        $result = $this->get_login_data($user);
        $result['errors'] = false;
        if (isset($_SESSION['unloq_pwd_checked.' . $user->user_login])) {
            unset($_SESSION['unloq_pwd_checked.' . $user->user_login]);
        }
        if (isset($_SESSION['unloq_enroll_checked'])) {
            unset($_SESSION['unloq_enroll_checked']);
        }
        wp_send_json($result);
    }

    /**
     * Perform the actual authentication part
     * Data:
     *  - user=optional
     *  - password=optional
     *  - otp=optional
     */
    public function process_uq_login_step()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        if (isset($_SESSION['unloq_enroll_checked'])) {
            unset($_SESSION['unloq_enroll_checked']);
        }
        try {
            $user = $this->check_identity();
        } catch (Exception $e) {
            return wp_send_json(array(
                'errors' => $e->getMessage()
            ));
        }
        $userData = $this->get_login_data($user);
        // We have to check the password.
        if ($userData['authentication_type'] !== 'unloq_only') {
            // See if we have to check the password.
            if (!isset($_SESSION['unloq_pwd_checked.' . $user->user_login])) {
                $userPass = $this->utility->rgar($_POST, 'password', false);
                if (!wp_check_password($userPass, $user->data->user_pass, $user->ID)) {
                    return wp_send_json(array(
                        'errors' => 'Incorrect password'
                    ));
                }
                $_SESSION['unloq_pwd_checked.' . $user->user_login] = true;
            }
        }
        $method = $this->utility->rgar($_POST, 'method', false);
        /* IF we have password_only, we finalize the login process. */
        if ($userData['authentication_type'] === 'password_only') {
            return $this->start_session($user);
        }
        if ($userData['authentication_type'] !== 'unloq_only' && $method === 'EMAIL') {
            return wp_send_json(array(
                'errors' => 'Authentication method not supported'
            ));
        }
        if (!$method) {
            return wp_send_json(array(
                'errors' => 'Please select an authentication method'
            ));
        }
        if (!in_array($method, $userData['authentication_methods'])) {
            return wp_send_json(array(
                'errors' => 'Authentication method not supported'
            ));
        }
        /* If the user is not enrolled, we enroll him */
        if (!$userData['user']['enrolled'] && $method !== 'EMAIL') {
            $remote = wp_remote_post(self::$API_url . '/pair', array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->api_key,
                    'Content-Type' => 'application/json',
                ),
                'body' => json_encode(array(
                    'email' => $user->user_email
                ))
            ));
            if (is_wp_error($remote)) {
                return wp_send_json(array(
                    'errors' => 'An error occurred.'
                ));
            }
            $body = json_decode($remote['body'], true);

            if (isset($body['error'])) {
                return wp_send_json(array(
                    'errors' => $errors = $this->utility->rgars($body, 'error/message')
                ));
            }
            $qrUrl = $this->utility->rgars($body, 'result/qr_url', false);
            if ($qrUrl != false) {
                $_SESSION['unloq_enroll_checked'] = $user->ID;
                return wp_send_json(array(
                    'errors' => false,
                    'qr_url' => $qrUrl
                ));
            }
        }
        /* Check the method used. */
        $sendParams = array(
            'email' => $user->user_email,
            'method' => $method,
            'ip' => $this->utility->getIp(),
            'generate_token' => false,
            'user_agent' => $_SERVER['HTTP_USER_AGENT']
        );
        $token = $this->utility->rgar($_POST, 'token', false);
        if ($method === 'EMAIL') {
            $sendParams['email_login_url'] = get_site_url();
        }
        if ($method === 'OTP' && $token == false) {
            return wp_send_json(array(
                'errors' => 'Please enter the OTP',
                'code' => 'APPROVAL.TOKEN'
            ));
        }
        if ($token != false) {
            $sendParams['token'] = $token;
        }
        $remote = wp_remote_post(self::$API_url . '/authenticate', array(
            'timeout' => 32,
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
                'Transfer-Encoding' => 'chunked'
            ),
            'body' => json_encode($sendParams)
        ));
        if (is_wp_error($remote)) {
            return wp_send_json(array(
                'errors' => 'An error occurred. Please try again'
            ));
        }
        $body = json_decode($remote['body'], true);
        if (isset($body['error'])) {
            $errors = $this->utility->rgars($body, 'error/message');
            $errorCode = $this->utility->rgars($body, 'error/code');
            return wp_send_json(array(
                'errors' => $errors,
                'code' => $errorCode
            ));
        }
        $result = array();
        if (isset($body['result'])) {
            $result = $body['result'];
        }
        $api_status_code     = $remote['response']['code'];
        $api_status_message  = $remote['response']['message'];
        //Only run start_session if API returns absolutely confirmed approval to login. Device offline or timeout returns 502 which passes!
        if( $api_status_code === 200 && $api_status_message === "OK" && isset( $result['approval_id'] ) ){
            // Start session
            if ($method === 'UNLOQ' || $method === 'OTP') {
                return $this->start_session($user, true, $result);
            }
            return wp_send_json(array(
                'errors' => false
            ));
        }
        return wp_send_json(array(
            'errors' => 'An error occurred. Please try again'
        ));
    }

    /**
     * This will initiate the password reset for the given user.
     */
    public function process_uq_login_reset_send()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        try {
            $user = $this->check_identity();
        } catch (Exception $e) {
            return wp_send_json(array(
                'errors' => $e->getMessage()
            ));
        }
        $userData = $this->get_login_data($user, false);
        if ($userData['authentication_type'] == 'unloq_only') {
            return wp_send_json(array(
                'errors' => 'This account role does not allow password resets.'
            ));
        }
        // Fires before errors are returned from a password reset
        $errors = false;
        do_action('lostpassword_post', $errors);
        $user_login = $user->user_login;
        $email = $user->user_email;
        $key = $this->utility->generate_user_activation_key($email);
        $link = $this->utility->login_site_url(array(
            'action' => 'rp',
            'key' => $key,
            'login' => rawurlencode($user_login),
        ));
        $message = __('Someone requested that the password be reset for the following account:') . "\r\n\r\n";
        $message .= network_home_url('/') . "\r\n\r\n";
        $message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
        $message .= __('If this was a mistake, just ignore this email and nothing will happen.') . "\r\n\r\n";
        $message .= __('To reset your password, visit the following address:') . "\r\n\r\n";
        $message .= '<' . $link . ">\r\n";
        $message = apply_filters('retrieve_password_message', $message, $key);
        $sent = $this->utility->send_password_notification_email($email, 'Password Reset', $message);

        if ($sent !== true) {
            $errors = $sent;
        }
        wp_send_json(array(
            'errors' => $errors
        ));
    }

    /**
     * This step is executed by the QR card to check if
     * the user is enrolled or not.
     */
    public function process_uq_login_enrolled()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        if (!isset($_SESSION['unloq_enroll_checked'])) {
            return wp_send_json(array(
                'errors' => 'Please initiate the enroll process'
            ));
        }
        $userId = $_SESSION['unloq_enroll_checked'];
        $user = get_user_by('id', $userId);
        if (!$user) {
            return wp_send_json(array(
                'errors' => 'This user does not exist anymore'
            ));
        }
        // Check enroll status.
        $remote = wp_remote_get(self::$API_url . '/pair/check?email=' . $user->user_email, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            )
        ));
        $body = json_decode($remote['body'], true);
        if (is_wp_error($remote)) {
            return wp_send_json(array(
                'errors' => 'An error occurred.'
            ));
        }
        if (isset($body['error'])) {
            return wp_send_json(array(
                'errors' => $errors = $this->utility->rgars($body, 'error/message')
            ));
        }
        $enrolled = $this->utility->rgars($body, 'result/enrolled');
        if ($enrolled != true) {
            return wp_send_json(array(
                'errors' => false
            ));
        }
        // User enrolled. We auto-logim
        return $this->start_session($user);
    }

    /**
     * Forgets the prelogged user.
     */
    public function process_uq_login_forget()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;
        if (!session_id()) session_start();
        if (isset($_SESSION['unloq_enroll_checked'])) {
            unset($_SESSION['unloq_enroll_checked']);
        }
        if (isset($_COOKIE['wp_unloq_prelogged'])) {
            $userName = $_COOKIE['wp_unloq_prelogged'];
            if (isset($_SESSION['unloq_pwd_checked.' . $userName])) {
                unset($_SESSION['unloq_pwd_checked.' . $userName]);
            }
            $this->clear_prelogged();
        }
        return wp_send_json(array(
            'errors' => false
        ));
    }

    /**
     * Clears the prelogged cookie information
     * */
    private function clear_prelogged()
    {
        if (isset($_COOKIE['wp_unloq_prelogged'])) {
            unset($_COOKIE['wp_unloq_prelogged']);
        }
        setcookie('wp_unloq_prelogged', '', time() - (15 * 60), COOKIEPATH, COOKIE_DOMAIN);
    }

    /**
     * Sets prelogged cookie information
     * This info will persist for 14 days.
     * */
    private function set_prelogged($userName, $secure_cookie)
    {
        $expire = time() + 60 * 60 * 24 * 14;
        setcookie('wp_unloq_prelogged', $userName, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_cookie, true);
        $_COOKIE['wp_unloq_prelogged'] = $userName;
    }


    /**
     * Collect login token and rediect to login page
     *
     * @since 1.0.4
     * @return void
     */
    public function collect_login_token()
    {
        $token = $this->utility->rgar($_GET, 'unloq-token', false);
        if ($token !== false) {
            $link = $this->utility->login_site_url(array(
                'action' => 'auth_email',
                'uqt' => $token
            ));
            wp_redirect($link);
            exit;
        }
    }


    /**
     *
     * @since    1.0.0
     */
    public function do_parse_request(&$wp)
    {
        $slug = $this->utility->rgar($this->settings, 'unloq_login_path', 'unloq');
        if (array_key_exists($slug, $wp->query_vars)) {
            echo $this->output_login_widget();
            exit;
        }

    }


    /**
     *
     * @since    1.0.0
     */
    public function add_custom_vars($vars)
    {
        $slug = $this->utility->rgar($this->settings, 'unloq_login_path', 'unloq');

        $vars[] = $slug;
        return $vars;
    }


    /**
     *
     * @since    1.0.0
     */
    public function custom_rewrite_rule()
    {
        $slug = $this->utility->rgar($this->settings, 'unloq_login_path', 'unloq');
        flush_rewrite_rules();
        add_rewrite_rule(
            '^' . $slug . '$/?',
            'index.php?' . $slug . '=1',
            'top'
        );
    }


    /**
     *
     * @since    1.0.0
     */
    public function output_login_widget()
    {
        $content = '';
        $template = '/ui/login-card.html';
        if (isset($_GET['action']) && $_GET['action'] == 'register') {
            $template = '/ui/register-card.html';
        }
        $file = apply_filters('uq_output_login_widget', UQ_VENDORS_DIR . $template);

        if (file_exists($file)) {

            ob_start();

            include $file;

            $content = ob_get_clean();

            $widget_welcome_text = $this->utility->rgar($this->customise, 'welcome_text') != '' ? '<div id="welcome-text">' . $this->utility->rgar($this->customise, 'welcome_text') . '</div>' : '';

            $customization = $this->customise;
            if (!isset($customization) || $customization === false) {
                $customization = array();
            }
            $wpVars = $this->get_page_data();
            $rep = array(
                '{plugin_version}',
                '{plugin_url}',
                '{wpVars}',
                '{wpCustomize}',
                '{widget_welcome_text}',
                '{style_css}',
            );
            $rep_w = array(
                UQ_VERSION,
                UQ_VENDORS . '/ui',
                json_encode($wpVars),
                json_encode($customization),
                $widget_welcome_text,
                '<style>
                body{
                    height: 100%;
                    min-height:100%;
                    background-size: cover;
                    background-position: center center;
                    background-image: url(' . $this->utility->rgar($this->customise, 'image_login_background_image') . ');
                }
                #logo-holder{
                    max-width: 240px;
                    height: 96px;
                    position: absolute;
                    top: 100px;
                    left: 50%;
                    margin-left: -500px;
                    overflow: hidden;
                }
                #logo-holder img{
                    max-width: 100%;
                }
                @media(max-width: 1024px){
                    #logo-holder{
                        position: relative;
                        top: 20px;
                        left: auto;
                        margin: 0 auto;
                    }
                }
                #welcome-text{
                    text-align: center;
                    font-size: 22px;
                    padding-top: 50px;
                }
                #uapp a {
                  color: ' . $this->utility->rgar($this->customise, "color_link", "#3da0e3") . ';
                }
                #uapp .widget-button > button,
                #uapp .widget-container .success-container {
                  background-color: ' . $this->utility->rgar($this->customise, "color_primary", "#000000") . ' !important;
                }
                #uapp .widget-button .spinner > circle {
                  stroke: ' . $this->utility->rgar($this->customise, "color_primary", "#000000") . ' !important;
                }
                #uapp .app-error {
                  color: ' . $this->utility->rgar($this->customise, "color_error", "#fd5252") . ' !important;
                }

                </style>'
            );
            $content = str_replace($rep, $rep_w, $content);
        }
        return $content;
    }


    /**
     *
     * @since    1.0.0
     */
    public function get_auth_by_role($role = null)
    {
        if (is_null($role)) return false;
        $auth_methods = $this->utility->rgar($this->settings, 'authentication_roles');
        if (isset($auth_methods[$role])) return $auth_methods[$role];
        return false;
    }


    /**
     * Register the stylesheets for the public-facing side of the site.
     *
     * @since    1.0.0
     */
    public function enqueue_styles()
    {
        wp_register_style('uq-loader', UQ_VENDORS . '/ui/css/loader.css', array(), UQ_VERSION, 'all');
        wp_register_style('uq-login', UQ_VENDORS . '/ui/css/card.css', array(), UQ_VERSION, 'all');
        wp_register_style('uq-register', UQ_VENDORS . '/ui/css/card.css', array(), UQ_VERSION, 'all');
    }

    /**
     * Register the JavaScript for the public-facing side of the site.
     *
     * @since    1.0.0
     */
    public function enqueue_scripts()
    {
        $wpVars = $this->get_page_data();
        wp_register_script('uq-login', UQ_VENDORS . '/ui/js/login-card.js', array(), UQ_VERSION, true);
        wp_register_script('uq-register', UQ_VENDORS . '/ui/js/register-card.js', array(), UQ_VERSION, true);
        wp_localize_script('uq-login', 'wpVars', $wpVars);
        wp_localize_script('uq-register', 'wpVars', $wpVars);
    }


    /**
     *
     * @since    1.0.0
     */
    public function authenticate_widget_shortcode()
    {
        wp_enqueue_style('uq-loader');
        wp_enqueue_style('uq-login');
        wp_enqueue_script('uq-login');
        ob_start();
        include UQ_VENDORS_DIR . '/ui/login-shortcode.html';
        return ob_get_clean();
    }


    /**
     *
     * @since    1.0.0
     */
    public function register_widget_shortcode()
    {
        wp_enqueue_style('uq-loader');
        wp_enqueue_style('uq-register');
        wp_enqueue_script('uq-register');
        ob_start();
        include UQ_VENDORS_DIR . '/ui/login-shortcode.html';
        return ob_get_clean();
    }

    /**
     * Consumes an UNLOQ token. Returns true if all is OK,
     * or a string as the error name.
     * */
    private function consume_token($token)
    {
        if (!isset($token) || !strlen($token)) return __('An error occurred (Missing token)', 'unloq');
        if (!session_id()) {
            session_start();
        }
        $remote = wp_remote_post('https://api.unloq.io/v1/token', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type' => 'application/json',
            ),
            'body' => json_encode(array(
                'token' => $token,
                'sid' => session_id(),
                'duration' => 30,
            ))
        ));
        if (is_wp_error($remote)) {
            return __("An error occurred while finalizing authentication.", "unloq");
        }
        $body = json_decode($remote['body'], true);
        if (!$body) return __("An error occurred while reading response", "unloq");
        if (isset($body['error'])) {
            return $this->utility->rgars($body, 'error/message');
        }
        $uq_email = $this->utility->rgars($body, 'result/email');
        $user = get_user_by('email', $uq_email);
        // Check if WP registration is enabled. If so, we will create the user.
        if (isset($user) && $user) {
            $this->start_session($user, false);
            return true;
        }
        // Check if the WP site has registration active.
        if (!get_option('users_can_register')) {
            return __('Registration is currently disabled.', 'unloq');
        }
        $username = str_replace("@", ".", $uq_email);
        $username = str_replace("_", ".", $username);
        $exists = username_exists($username);
        if ($exists) {
            $username .= rand(1000, 9999);
        }
        // We have to generate a 64-random char password.
        $userPass = wp_generate_password(32, false);
        $newUser = new stdClass();
        $newUser->user_email = $uq_email;
        $newUser->user_login = $username;
        $newUser->user_pass = $userPass;
        $firstName = $this->utility->rgars($body, 'result/first_name');
        $lastName = $this->utility->rgars($body, 'result/last_name');
        if (isset($firstName) && $firstName) {
            $newUser->first_name = $firstName;
        }
        if (isset($lastName) && $lastName) {
            $newUser->last_name = $lastName;
        }
        $registered = wp_insert_user($newUser);
        if (is_wp_error($registered)) {
            return __('Could not create new user', 'unloq');
        }
        $user = get_user_by('email', $uq_email);
        if (is_wp_error($user)) {
            return __('Failed to perform registration, could not read user', 'unloq');
        }
        $this->start_session($user, false);
        return true;
    }


    /**
     *
     * @since    1.0.0
     */
    public function process_uq_login_reset()
    {
        if (!check_ajax_referer('unloq_key', 'security', false)) return;

        $newPass = $this->utility->rgar($_POST, 'password');
        $login = $this->utility->rgar($_POST, 'login');
        $key = $this->utility->rgar($_POST, 'key');
        $errors = false;
        $user = get_user_by('login', $login);
        if (!$key || !$login || !$newPass) {
            return wp_send_json(array(
                'code' => 'LINK_EXPIRED',
                'errors' => 'Invalid reset credentials'
            ));
        }
        if (!$user) {
            return wp_send_json(array(
                'code' => 'LINK_EXPIRED',
                'errors' => 'The user no longer exists'
            ));
        }
        $check_key = check_password_reset_key($key, $user->user_login);
        if (is_wp_error($check_key)) {
            return wp_send_json(array(
                'code' => 'LINK_EXPIRED',
                'errors' => 'The password reset link has expired.'
            ));
        }
        //Fires before the password reset procedure is validated.
        do_action('validate_password_reset', $errors, $user);
        if ($errors) {
            return wp_send_json(array(
                'errors' => $errors
            ));
        }
        // Finally, update password.
        wp_set_password($newPass, $user->ID);
        wp_send_json(array(
            'errors' => false,
        ));
    }


    /**
     * ============ V1.X COMPATIBILITY MODE CODE ==============
     * Registers all the login form actions from v1.x plugin
     * to render the old plugin as usual.
     */
    private function sso_init()
    {
        if (!isset($this->settings['sso']) || $this->settings['sso'] !== 'true') return;
        add_action('init', array($this, "sso_request_start"), 2);
    }


    public function uauth_token_login()
    {
        if (!isset($_GET['token']) || !strlen($_GET['token'])) return;
        $token = $_GET['token'];
        if(substr($token, 0, 2) !== 'AU') return;
        if(strlen($token) < 100) return;
        $isLogged = $this->consume_token($token);
        if ($isLogged !== true) {
            $this->utility->flash($isLogged);
            wp_redirect(wp_login_url());
            exit;
        }
        $user = wp_get_current_user();
        parse_str($this->utility->rgar($_GET, 'query'), $query);
        $redirect_to = $this->utility->rgar($query, 'redirect_to', admin_url('index.php'));
        $requested_redirect_to = isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '';
        $redirectTo = apply_filters('login_redirect', $redirect_to, $requested_redirect_to, $user);
        wp_redirect($redirectTo);
        exit;
    }

    /**
     * Registered in v1-compat mode, called when the request starts
     * to block login requests.
     */
    public function sso_request_start()
    {
        if (is_admin()) return;
        if (!isset($GLOBALS['pagenow']) || $GLOBALS['pagenow'] !== 'wp-login.php') return;
        if (!session_id()) session_start();
        wp_enqueue_script('uq-login-compat', UQ_VENDORS . '/ui/js/login.compat.js', array('jquery'), UQ_VERSION, true);
        wp_enqueue_style('uq-login-compat', UQ_VENDORS . '/ui/css/login.compat.css', array(), UQ_VERSION, 'all');
        add_action('login_form', array($this, "sso_init_form"), 1);
        add_action('login_body_class', array($this, "sso_init_classes"), 1);
        add_filter('wp_login_errors', array($this, 'sso_login_errors'));

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        // IF only the UNLOQ login way is enabled, we block anything else.
        $action = strtolower(isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login');
        if ($action != 'login' && $action != 'postpass' && $action != 'register' && $action != 'retrievepassword' && $action != 'lostpassword' && $action != 'resetpass' && $action != 'rp') {
            return;
        }
        if ($action == "login" || $action == "logout") {
            if (isset($_REQUEST['redirect_to'])) {
                // We temporary save the redirect_to to the session.
                $this->utility->flash("redirect_to", $_REQUEST["redirect_to"]);
            }
        }
        // Only when we're unloq-only, do we block everything
        if ($this->settings['authentication_type'] !== 'unloq_only') return;
        switch ($action) {
            case "postpass":
            case "register":
                $this->utility->flash("In order to register to the site, please login with UNLOQ.");
                break;
            case "retrievepassword":
            case "lostpassword":
            case "resetpass":
            case "rp":
                $this->utility->flash("Password reset is currently disabled.");
                break;
            default:
                $this->utility->flash("This action has been disabled by the administrator", "error");
        }
        wp_redirect(wp_login_url());
        exit;
    }

    /*
     * Initializes the login form compat
     * */
    public function sso_init_form()
    {
        $loginType = 'UNLOQ_PASS';
        if ($this->settings['authentication_type'] === 'unloq_only') {
            $loginType = 'UNLOQ';
        }
        $this->utility->render('/login', array(
            'unloq_type' => $loginType,
            'unloq_widget_key' => $this->settings['login_widget_key']
        ));
    }

    public function sso_init_classes($classes)
    {
        // If we're on the login page, we add classes to the body
        if (in_array("login-action-login", $classes)) {
            if ($this->settings['authentication_type'] == "unloq_only") {    // unloq-only
                array_push($classes, "unloq-only");
            } else {
                array_push($classes, "unloq-pass");
            }
        }
        return $classes;
    }

    /**
     * Renders flash-added errors for compat mode.
     * */
    public function sso_login_errors($errors)
    {
        $flashes = $this->utility->flash();
        foreach ($flashes as $err) {
            if ($err['type'] == 'error') {
                $errors->add('unloq_error', $err['message']);
            }
        }
        $this->utility->clearFlash();
        return $errors;
    }

}

Wp_Unloq_Login::instance();
