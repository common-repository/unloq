<?php

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/includes
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */
class Wp_Unloq_Activator
{

    protected $util;

    public function __construct()
    {
        $this->util = new Wp_Unloq_Utility();
    }

    /**
     * Short Description. (use period)
     *
     * Long Description.
     *
     * @since    1.0.0
     */
    public function activate()
    {
        $this->checkUpgrade();
    }

    /**
     * Verify the plugin version and perform upgrades from previous versions.
     *
     */
    private function checkUpgrade()
    {
        $currentVersion = $this->util->wp_option('get', 'unloq_version');
        if (version_compare($currentVersion, UQ_VERSION, '=='))
            return;
        $this->upgradeFromVersionOne();
        // we store the current plugin version
        $this->util->wp_option('update', 'unloq_version', UQ_VERSION);
    }


    /**
     * Migrates settings, upgrading UNLOQ plugin from 1.x versions to 2.x version
     *
     */
    private function upgradeFromVersionOne()
    {
        global $wp_roles;
        $oldSettings = unserialize($this->util->wp_option('get', 'wpunloq'));
        if (!isset($oldSettings) || !is_array($oldSettings) || !isset($oldSettings['api_secret']) || !isset($oldSettings['api_key'])) return;
        $customAdminUrl = $this->util->wp_option('get', 'unloq_custom_admin_url', 'wp-login.php');
        if (!$this->util->isCustomLoginPathDisabled()) {
            $customAdminUrl = 'wp-login.php';
        }
        $oldApiKey = $oldSettings['api_secret'];
        $oldWidgetKey = $oldSettings['api_key'];
        if (!strlen($oldApiKey) || !strlen($oldWidgetKey)) return;
        $newApiKey = $this->util->get_migration_info($oldApiKey, 'POST', 'credentials/regenerate', array(
            'url' => get_bloginfo('url'),
            'application_name' => get_bloginfo('name') || 'WP Site',
            'platform' => 'WORDPRESS'
        ));

        // we check if the apiKey is set and valid from old settings
        // and only in this case we proceed with migrating data
        if ($newApiKey !== false) {
            // we set the values for wp_options.unloq_credentials
            $unloqCredentials = array(
                'api_key' => $newApiKey->api_key,
                'application_id' => $newApiKey->application_id
            );
            $this->util->wp_option('update', 'unloq_credentials', $unloqCredentials);

            // we save the wp_options.unloq_customize
            $unloqCustomize = (array)$this->util->get_migration_info($newApiKey->api_key, 'GET', 'customize');
            $this->util->wp_option('update', 'unloq_customise', $unloqCustomize);

            // we save the wp_options.unloq_settings
            $settings = $this->util->get_migration_info($newApiKey->api_key, 'GET', 'settings');

            $unloqSettings = isset($settings) ? (array)$settings : array();
            $unloqSettings['login_widget_key'] = $oldWidgetKey;
            $unloqSettings['sso'] = 'true';
            $unloqSettings['wp_roles'] = $wp_roles->get_names();

            // we set the default authentication method 'password_only' for the roles
            foreach ($unloqSettings['wp_roles'] as $roleId => $role) {
                $authenticationRoles[$roleId] = 'password_only';
            }

            $unloqSettings['authentication_roles'] = $authenticationRoles;

            $unloqSettings['unloq_login_path'] = 'unloq';
            $unloqSettings['wp_login_path'] = $customAdminUrl;

            // on upgrade, we allow the user to login using wp standard login
            $unloqSettings['wp_login_active'] = 'true';

            $unloqSettings['authentication_type'] = $this->setAuthenticationType($oldSettings);

            $this->util->wp_option('update', 'unloq_settings', $unloqSettings);

            // remove the setting from the old plugin
            $this->util->wp_option('delete', 'wpunloq');
            $this->util->wp_option('delete', 'unloq_custom_admin_url');
            $this->util->wp_option('delete', 'unloq__login_text_color');
            $this->util->wp_option('delete', 'unloq__login_box_color');
            $this->util->wp_option('delete', 'unloq__login_body_color');
            $this->util->wp_option('delete', 'UNLOQ_ACTIVE');
        }
    }

    /**
     * Retrieves the authentication type from the old plugin if it
     * is set and returns the type that should be further used
     *
     * @param $oldSettings
     *
     * @return string
     */
    protected function setAuthenticationType($oldSettings)
    {
        $type = 'password_only';

        if (isset($oldSettings['login_type'])) {
            switch ($oldSettings['login_type']) {
                case 'UNLOQ_PASS':
                    $type = 'unloq_second_factor';
                    break;
                case 'UNLOQ':
                    $type = 'unloq_only';
                    break;
            }
        }

        return $type;
    }
}
