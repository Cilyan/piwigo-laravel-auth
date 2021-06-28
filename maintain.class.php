<?php
defined('PHPWG_ROOT_PATH') or die('Hacking attempt!');

class LaravelAuth_maintain extends PluginMaintain
{
  private $default_conf = array(
  );

  function install($plugin_version, &$errors=array())
  {
    global $conf;

    if (empty($conf['LaravelAuth']))
    {
      conf_update_param('LaravelAuth', $this->default_conf, true);
    }
  }

  function update($old_version, $new_version, &$errors=array())
  {
    $this->install($new_version, $errors);
  }

  function uninstall()
  {
    conf_delete_param('LaravelAuth');
  }
}
