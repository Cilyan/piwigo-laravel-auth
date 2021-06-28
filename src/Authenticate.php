<?php

namespace LaravelAuth;

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class Authenticate
{
    protected $provider = null;
    
    public function __construct()
    {
        $this->provider = new GenericProvider([
            'clientId'                => '93c8c736-d87e-42d7-a9dc-bb87d6c8f89c',
            'clientSecret'            => 'cccqgXcKdf3Wggq0c2i9NrrkSyHCkDomNhpLeB0Z',
            'redirectUri'             => get_absolute_root_url().'identification.php',
            'urlAuthorize'            => 'https://homestead.cilyan.org/oauth/authorize',
            'urlAccessToken'          => 'https://homestead.cilyan.org/oauth/token',
            'urlResourceOwnerDetails' => 'https://homestead.cilyan.org/api/user'
        ]);
    }
    
    public function authenticate()
    {
        // If we don't have an authorization code then get one
        if (!isset($_GET['code'])) {
            
            $this->request_code();
            
            // Check given state against previously stored one to mitigate CSRF attack
        }
        else {
            $this->callback();
        }
    }
    
    private function request_code()
    {
        // Fetch the authorization URL from the provider; this returns the
        // urlAuthorize option and generates and applies any necessary parameters
        // (e.g. state).
        $authorizationUrl = $this->provider->getAuthorizationUrl();
        
        // Get the state generated for you and store it to the session.
        $_SESSION['oauth2state'] = $this->provider->getState();
        $this->set_redirect();
        
        // Redirect the user to the authorization URL.
        redirect($authorizationUrl);
        // Doesn't return.
    }
    
    private function callback()
    {
        if (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
            
            if (isset($_SESSION['oauth2state'])) {
                unset($_SESSION['oauth2state']);
            }
            
            $this->die_with_error();
            
        } else {
            try {
                // Try to get an access token using the authorization code grant.
                $accessToken = $this->provider->getAccessToken('authorization_code', [
                    'code' => $_GET['code']
                ]);
                
                // We have an access token, which we may use in authenticated
                // requests against the service provider's API.
                //echo 'Access Token: ' . $accessToken->getToken() . "<br>";
                //echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
                //echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
                //echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";
                
                // Using the access token, we may look up details about the
                // resource owner.
                $resourceOwner = $this->provider->getResourceOwner($accessToken);
                
                $user = $resourceOwner->toArray();
                
            } catch (IdentityProviderException $e) {
                // Failed to get the access token or user details.
                exit($e->getMessage());
            }

            $success = $this->log_or_create_user($user);

            if ($success === true)
            {
                $this->redirect();
            }
            
            $this->die_with_error();
        }
    }
    
    private function die_with_error()
    {
        set_status_header(401);
        
        echo '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">';
        echo '<div style="text-align:center;">'.l10n('You are not authorized to access the requested page').'<br>';
        echo '<a href="'.get_root_url().'identification.php">'.l10n('Identification').'</a>&nbsp;';
        echo '<a href="'.make_index_url().'">'.l10n('Home').'</a></div>';
        echo str_repeat( ' ', 512); //IE6 doesn't error output if below a size
        exit();
    }
    
    private function log_or_create_user(array $user)
    {
        global $conf;
        
        $userid = get_userid_by_email($user['email']);

        if ($userid !== false) {
            // if user status is "guest" then she should not be granted to log in.
            // The user may not exist in the user_infos table, so we consider it's a "normal" user by default
            $status = 'normal';
            
            $query = '
            SELECT * FROM '.USER_INFOS_TABLE.'
                WHERE user_id = '.$userid.'
            ;';
            $result = pwg_query($query);
            while ($user_infos_row = pwg_db_fetch_assoc($result))
            {
                $status = $user_infos_row['status'];
            }
            
            if ('guest' == $status)
            {
                // Invalidate user
                $userid = null;
            }
        }
        else {
            $userid = $this->register_user($user);
        }
        
        if ($userid !== false)
        {
            log_user($userid, true);
            trigger_notify('login_success', stripslashes($user['email']));
            return true;
        }
        trigger_notify('login_failure', stripslashes($user['email']));
        return false;
    }
    
    private function set_redirect()
    {
        if (isset($_POST['redirect'])) {
            $redirect_to = urldecode($_POST['redirect']);
            // security (level 2): force redirect within Piwigo. We redirect to
            // absolute root url, including http(s)://, without the cookie path,
            // concatenated with $_POST['redirect'] param.
            //
            // example:
            // {redirect (raw) = /piwigo/git/admin.php}
            // {get_absolute_root_url = http://localhost/piwigo/git/}
            // {cookie_path = /piwigo/git/}
            // {host = http://localhost}
            // {redirect (final) = http://localhost/piwigo/git/admin.php}
            $root_url = get_absolute_root_url();
            $intended = substr(
                $root_url,
                0,
                strlen($root_url) - strlen(cookie_path())
            ).$redirect_to;
        }
        else {
            $intended = get_gallery_home_url();
        }
        $_SESSION['oauth_intended'] = $intended;
    }
    
    private function redirect()
    {
        $redirect = isset($_SESSION['oauth_intended']) 
        ? $_SESSION['oauth_intended']
        : get_gallery_home_url();
        redirect($redirect);
    }

    private function register_user(array $user)
    {
        $conf['password_hash'] = function ($password) { return $password; };
        $userid = register_user($user['name'], null, $user['email'], false);
        // If user is admin, use status admin
        if (    $user['is_admin'] === 1
             && $userid != $conf['webmaster_id']
             && $userid != $conf['guest_id']
             && $userid != $conf['default_user_id']
             && $userid !== false
        ) {
            $query = '
            UPDATE '. USER_INFOS_TABLE .' SET
                status = "admin"
                WHERE user_id = '.$userid.'
            ;';
            pwg_query($query);
        }
        return $userid;
    }
}