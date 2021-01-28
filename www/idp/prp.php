<?php

/**
 * ADFS PRP IDP protocol support for SimpleSAMLphp.
 *
 * @author Hans Zandbelt, SURFnet bv, <hans.zandbelt@surfnet.nl>
 * @package SimpleSAMLphp
 */

/** Office clients often request things in an embedded ie11 browser which has two problems
 * 1. It is likely not the default client so user has no SSO session
 * 2. ie11 does not support javascript 6 which may cause numerous JS errors in the embedded window
 *
 * Microsoft's suggested fix is to return a 200 with a meta refresh. Office interprets this as
 * "request the url again, but in the user's default browser". See http://support.microsoft.com/kb/899927
 *
 * "For an HTTP request that may be a multiple-session client request, issue a client-side redirect response instead of a server-side redirect response. For example, send an HTTP script or a META REFRESH tag instead of an HTTP 302 response. This change forces the client back into the default Web browser of the user. Therefore, the default browser session can handle the call and can keep the call in a single, read-only session."
 */

if ((strpos($_SERVER['HTTP_USER_AGENT'] ?? "", 'Trident') > 0))
{
    // ie11 browser needs refresh to force use of default browser
    if (array_key_exists('refreshed', $_GET)) {
        SimpleSAML\Logger::info('ie11 refreshed but did not trigger Office to open non-ie11 browser. Continue normally');
    } else {
        SimpleSAML\Logger::info('sending metarefresh to ie11 to open non-ie11 browser');
        // add a refreshed query parameter to avoid any looping.
        $currentRequest = $_SERVER['REQUEST_URI'];
        if (strpos($currentRequest, '?') !== false) {
            $currentRequest .= '&refreshed=yes';
        } else {
            $currentRequest .= '?refreshed=yes';
        }
        echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"';
        echo ' "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">' . "\n";
        echo '<html xmlns="http://www.w3.org/1999/xhtml">' . "\n";
        echo "  <head>\n";
        echo '    <meta http-equiv="content-type" content="text/html; charset=utf-8">' . "\n";
        echo '    <meta http-equiv="refresh" content="0;URL=\'' . htmlspecialchars($currentRequest) . '\'">' . "\n";
        echo "    <title>Redirect</title>\n";
        echo "  </head>\n";
        echo "  <body>\n";
        echo "<p>Sending metarefresh to work around Office embedded ie11</p>";
        echo "  </body>\n";
        echo '</html>';
        exit();
    }
}

\SimpleSAML\Logger::info('ADFS - IdP.prp: Accessing ADFS IdP endpoint prp');

$metadata = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
$idpEntityId = $metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
$idp = \SimpleSAML\IdP::getById('adfs:'.$idpEntityId);

if (isset($_GET['wa'])) {
    if ($_GET['wa'] === 'wsignout1.0') {
        \SimpleSAML\Module\adfs\IdP\ADFS::receiveLogoutMessage($idp);
    } elseif ($_GET['wa'] === 'wsignin1.0') {
        \SimpleSAML\Module\adfs\IdP\ADFS::receiveAuthnRequest($idp);
    }
    throw new \Exception("Code should never be reached");
} elseif (isset($_GET['assocId'])) {
    // logout response from ADFS SP
    $assocId = $_GET['assocId']; // Association ID of the SP that sent the logout response
    $relayState = $_GET['relayState']; // Data that was sent in the logout request to the SP. Can be null
    $logoutError = null; // null on success, or an instance of a \SimpleSAML\Error\Exception on failure.
    $idp->handleLogoutResponse($assocId, $relayState, $logoutError);
}
