<?php

// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package    local_jwttomoodletoken
 * @author     Nicolas Dunand <nicolas.dunand@unil.ch>
 * @author     Amer Chamseddine <amer@pocketcampus.org>
 * @copyright  2023 Copyright PocketCampus Sàrl {@link https://pocketcampus.org/}
 * @copyright  based on work by 2020 Copyright Université de Lausanne, RISET {@link http://www.unil.ch/riset}
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/externallib.php');
require_once($CFG->libdir . '/filelib.php'); // Moodle cURL wrapper.

class local_jwttomoodletoken_external extends external_api {

    /**
     * @return external_multiple_structure
     */
    public static function gettoken_returns() {
        return new external_single_structure([
                'moodletoken' => new external_value(PARAM_ALPHANUM, 'valid Moodle mobile token')
        ]);
    }

    /**
     * @param $useremail
     * @param $since
     *
     * @return array
     * @throws coding_exception
     * @throws invalid_parameter_exception
     */
    public static function gettoken($accesstoken) {
        global $CFG, $DB, $PAGE, $SITE, $USER;
        $PAGE->set_url('/webservice/rest/server.php', []);
        $params = self::validate_parameters(self::gettoken_parameters(), [
                'accesstoken' => $accesstoken
        ]);

        $userinfo_url = get_config('local_jwttomoodletoken', 'userinfo_url');
        $username_attribute = get_config('local_jwttomoodletoken', 'username_attribute');

        // Fetch UserInfo via Moodle cURL (replaces file_get_contents to avoid allow_url_fopen=0).
        $headers = [
            'Accept: application/json',
            'Authorization: Bearer ' . $params['accesstoken'],
        ];

        error_log('[jwttomoodletoken] using curl path on pod='.gethostname());

        $curl = new curl();
        $curl->setHeader($headers);
        $curl->setopt([
            'CURLOPT_CONNECTTIMEOUT' => 10,
            'CURLOPT_TIMEOUT'        => 20,
            'CURLOPT_SSL_VERIFYPEER' => true,
            'CURLOPT_SSL_VERIFYHOST' => 2,
        ]);

        $response = $curl->get($userinfo_url);
        $errno    = $curl->get_errno();
        $error    = $curl->error;
        $info     = $curl->get_info();
        $httpcode = isset($info['http_code']) ? (int)$info['http_code'] : 0;

        if ($errno) {
            // Network/TLS error before any HTTP response from PocketCampus.
            throw new moodle_exception('curlerror', 'local_jwttomoodletoken', '', null,
                'cURL error ' . $errno . ': ' . $error);
        }

        // Decode JSON body (even for non-2xx HTTP status results, their API returns JSON error objects).
        $user_attributes = json_decode((string)$response, true);
        if (!is_array($user_attributes)) {
            throw new moodle_exception('invalidresponse', 'local_jwttomoodletoken', '', null,
                'UserInfo did not return valid JSON (HTTP '.$httpcode.')');
        }

        // Handle API-level errors returned by UserInfo.
        if (isset($user_attributes['error']) && $user_attributes['error'] === 'invalid_grant') {
            throw new moodle_exception('invalidaccesstoken', 'webservice');
        }
        if (isset($user_attributes['error']) && $user_attributes['error']) {
            throw new moodle_exception('userinfoerror', 'webservice', '', $user_attributes);
        }
        // End cURL UserInfo.

        $username = $user_attributes[$username_attribute];
        if (is_array($username)) {
            $username = array_shift($username);
        }
        if (!$username) {
            throw new moodle_exception('usernamenotfound', 'webservice');
        }

        $user = $DB->get_record('user', [
                'username'  => $username,
                //'auth'      => 'shibboleth',
                'suspended' => 0,
                'deleted'   => 0
        ], '*', IGNORE_MISSING);
        if (!$user) {
            throw new moodle_exception('usernotfound', 'webservice', '', $username);
        }

        // Check if the service exists and is enabled.
        $service = $DB->get_record('external_services', [
                'shortname' => 'moodle_mobile_app',
                'enabled'   => 1
        ]);
        if (empty($service)) {
            throw new moodle_exception('servicenotavailable', 'webservice');
        }

        // Ugly hack.
        $realuser = $USER;
        $USER = $user;
        $token = external_generate_token_for_current_user($service);
        $USER = $realuser;

        external_log_token_request($token);

        return [
                'moodletoken' => $token->token
        ];
    }

    /**
     * @return external_function_parameters
     */
    public static function gettoken_parameters() {
        return new external_function_parameters([
                'accesstoken' => new external_value(PARAM_RAW_TRIMMED, 'the OAuth2 access_token')
        ]);
    }

}

