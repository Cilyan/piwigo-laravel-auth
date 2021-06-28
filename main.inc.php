<?php
/*
Plugin Name: Laravel Auth
Version: 0.1.0
Description: Authenticate users from a Laravel App using Passport
Plugin URI: 
Author: Cilyan Olowen
Author URI: https://blog.cilyan.org
*/

use LaravelAuth\PiwigoPlugin;

defined('PHPWG_ROOT_PATH') or die('Hacking attempt!');

require __DIR__ . '/vendor/autoload.php';

define('LARAVELAUTH_ID',       basename(dirname(__FILE__)));
define('LARAVELAUTH_PATH' ,    PHPWG_PLUGINS_PATH . LARAVELAUTH_ID . '/');
define('LARAVELAUTH_ADMIN',    get_root_url() . 'admin.php?page=plugin-' . LARAVELAUTH_ID);

$plugin = new PiwigoPlugin();
$plugin->register();
