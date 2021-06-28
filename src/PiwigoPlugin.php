<?php

namespace LaravelAuth;

use LaravelAuth\Authenticate;

class PiwigoPlugin
{
    public function register()
    {
        add_event_handler('init', [$this, 'init']);
        if (!defined('IN_ADMIN'))
        {
            add_event_handler('loc_begin_identification', [$this, 'loc_begin_identification']);
        }
        else
        {
            add_event_handler('get_admin_plugin_menu_links', [$this, 'get_admin_plugin_menu_links']);
        }
        add_event_handler('load_profile_in_template', [$this, 'load_profile_in_template']);
        add_event_handler('loc_begin_profile', [$this, 'loc_begin_profile']);
    }

    public function init()
    {
        global $conf;
        $conf['LaravelAuth'] = safe_unserialize($conf['LaravelAuth']);

        load_language('plugin.lang', LARAVELAUTH_PATH);
    }

    public function get_admin_plugin_menu_links($menu) 
    {
        $menu[] = array(
            'NAME' => 'Laravel Auth',
            'URL' => LARAVELAUTH_ADMIN,
            );

        return $menu;
    }

    public function loc_begin_identification()
    {
        $auth = new Authenticate();
        $auth->authenticate();
    }

    public function load_profile_in_template($userdata)
    {
        global $template;
        // Force all users to not be able to change email+password
        $template->assign('SPECIAL_USER', true);
    }

    public function loc_begin_profile()
    {
        unset(
            $_POST['username'],
            $_POST['mail_address'],
            $_POST['password'],
            $_POST['use_new_pwd'],
            $_POST['passwordConf']
        );
    }
}
