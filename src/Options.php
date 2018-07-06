<?php
/**
 * Options Class
 *
 * The options-specific functionality for WordPress.
 *
 * You may copy, distribute and modify the software as long as you track
 * changes/dates in source files. Any modifications to or software including
 * (via compiler) GPL-licensed code must also be made available under the GPL
 * along with build & install instructions.
 *
 * PHP Version 7.2
 *
 * @category  WPS
 * @package   WPS\Options
 * @author    Travis Smith <t@wpsmith.net>
 * @copyright 2018 Travis Smith; 2018 Akamai
 * @license   http://opensource.org/licenses/gpl-2.0.php GNU Public License v2
 * @link      https://github.com/akamai/wp-akamai
 * @since     0.2.0
 */

namespace WPS\Options;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WPS\Options' ) ) {
	/**
	 * Class Options
	 *
	 * @package Akamai\Open\WP
	 */
	abstract class Options extends \WPS\Core\Singleton {

		/**
		 * Plugin Version Number
		 */
		protected static $version = '0.0.1';

		/**
		 * The unique identifier of this plugin.
		 *
		 * @since    0.1.0
		 * @access   protected
		 * @var      string $plugin_name The string used to uniquely identify this plugin.
		 */
		protected static $plugin_name = 'fundraising';

		/**
		 * Nonce suffix.
		 */
		const NONCE = '-nonce';

		/**
		 * Nonce Value.
		 *
		 * @var string
		 */
		private static $nonce = '';

		/**
		 * Nonce Action.
		 *
		 * @var string
		 */
		protected static $nonce_action = '-nonce';

		/**
		 * Nonce $_POST name.
		 *
		 * WordPress looks for `_wpnonce` by default.
		 *
		 * @var string
		 */
		protected static $nonce_name = '-nonce';

		/**
		 * Array of Akamai Options.
		 *
		 * @var array
		 */
		protected static $options = array();

		/**
		 * Array of defaults for Akamai Options.
		 *
		 * @var array
		 */
		protected static $defaults = array();

		/**
		 * Options constructor.
		 */
		protected function __construct() {
			self::set_nonce_name();
			self::set_nonce_action();
		}

		/**
		 * Gets a single option from Akamai Options.
		 *
		 * @param string     $option  Option Key.
		 * @param mixed|null $default Fallback value if option not set.
		 *
		 * @return mixed|null
		 */
		public function get_option( $option, $default = null ) {
			$options = $this->get_options();

			if ( isset( $options[ $option ] ) ) {
				return $options[ $option ];
			}

			$options[ $option ] = $default;

			return $default;
		}

		/**
		 * Gets all Akamai Options.
		 *
		 * @param bool $fresh Whether to fetch options from DB or use cache.
		 *
		 * @return array|mixed Akamai Options.
		 */
		public function get_options( $fresh = false ) {
			// If cache ok & options already populated, return options.
			if ( ! empty( self::$options ) && ! $fresh ) {
				return self::$options;
			}

			// Get the options from WP DB.
			self::$options = get_option( self::$plugin_name, self::get_defaults() );

			// Ensure that auth_method is set (transfer method to auth_method) & update DB.
			if ( ! isset( self::$options['auth_method'] ) && isset( self::$options['method'] ) ) {
				self::$options['auth_method'] = self::$options['method'];
				unset( self::$options['method'] );
				self::update( self::$options );
			}

			// Return Fresh DB options.
			return self::$options;
		}

		/**
		 * Default Akamai Option values.
		 *
		 * @return array Default options values.
		 */
		abstract public function get_defaults();

		/**
		 * Gets a specific default option.
		 *
		 * @param string $option Option name/key.
		 *
		 * @return mixed|null
		 */
		public function get_default( $option ) {
			$defaults = $this->get_defaults();

			if ( isset( $defaults[ $option ] ) ) {
				return $defaults[ $option ];
			}

			return null;
		}

		/**
		 * Update the options.
		 *
		 * @param array $options Array of options.
		 */
		public static function update( $options ) {
			update_option( self::get_plugin_name(), $options );
			self::$options = $options;
		}

		/**
		 * Does a security check for Ajax & Admin.
		 *
		 * For DOING_AJAX, uses check_ajax_referer
		 * For other admin requests, uses check_admin_referer.
		 * Both WordPress functions do a wp_verify_nonce.
		 *
		 * @return bool
		 */
		public function check() {

			if ( self::doing_ajax() ) {
				if ( false === check_ajax_referer( Options::$nonce_action, Options::$nonce_name, false ) ) {
					wp_send_json_error( __( 'Unauthorized.', self::get_plugin_name() ) );
				}
			}

			if ( false === check_admin_referer( Options::$nonce_action, Options::$nonce_name ) ) {
				return false;
			}

			return ! (
				! isset( $_POST[ Options::$nonce_name ] ) ||
				( isset( $_POST[ Options::$nonce_name ] ) && ! wp_verify_nonce( sanitize_key( $_POST[ Options::$nonce_name ] ), Options::$nonce_action ) )
			); // Input var ok.

		}

		/**
		 * Helper function to determine whether doing AJAX or not.
		 *
		 * @return bool
		 */
		public static function doing_ajax() {
			return ( defined( 'DOING_AJAX' ) && DOING_AJAX );
		}

		/**
		 * Validates the necessary values from the form or AJAX methods.
		 *
		 * @param array $input Array of inputs from $_POST, etc.
		 *
		 * @return array Sanitized/Validated inputs.
		 */
		abstract public function sanitize( $input );

		/**
		 * Sets the Nonce values for name and action.
		 *
		 * @param string $value Nonce name prefix for name/action.
		 *
		 * @return void
		 */
		protected static function set_nonce_values( $value = '' ) {
			self::set_nonce_action( $value );
			self::set_nonce_name( $value );
		}

		/**
		 * Sets the Nonce name value.
		 *
		 * @param string $name Nonce name.
		 *
		 * @return void
		 */
		public static function set_nonce_name( $name = '' ) {
			$name = '' === $name ? self::get_plugin_name() : $name;

			self::$nonce_name = $name . self::NONCE;
		}

		/**
		 * Sets the Nonce action value.
		 *
		 * @param string $action Action name.
		 *
		 * @return void
		 */
		public static function set_nonce_action( $action = '' ) {
			$action = '' === $action ? self::get_plugin_name() : $action;

			self::$nonce_action = $action . self::NONCE;
		}

		/**
		 * Gets the Nonce.
		 *
		 * @return string
		 */
		public static function get_nonce() {
			if ( self::NONCE !== self::$nonce ) {
				return self::$nonce;
			}

			self::$nonce = wp_create_nonce( self::$nonce_action );

			return self::$nonce;
		}

		/**
		 * The name of the plugin used to uniquely identify it within the context of
		 * WordPress and to define internationalization functionality.
		 *
		 * @since     0.1.0
		 * @return    string    The name of the plugin.
		 */
		public static function get_plugin_name() {
			return self::$plugin_name;
		}

		/**
		 * Retrieve the version number of the plugin.
		 *
		 * @since     0.1.0
		 * @return    string    The version number of the plugin.
		 */
		public static function get_version() {
			return self::$version;
		}
	}
}

