<?php

/**
 * Define the internationalization functionality
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @link       http://www.superwpheroes.io/
 * @since      1.0.0
 *
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/includes
 */

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      1.0.0
 * @package    Wp_Unloq
 * @subpackage Wp_Unloq/includes
 * @author     Wordpressheroes.io <cosmin@wordpressheroes.io>
 */
class Wp_Unloq_i18n
{


    /**
     * Load the plugin text domain for translation.
     *
     * @since    1.0.0
     */
    public function load_plugin_textdomain()
    {

        load_plugin_textdomain(
            'unloq',
            false,
            dirname(dirname(plugin_basename(__FILE__))) . '/languages/'
        );

    }


}
