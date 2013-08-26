/**
 * WinJS_VimeoVideo
 * By Ola Karlsson
 * http://olakarlsson.com
 * Based on WinJS OAuth for Twitter v1.3
 * https://github.com/cauld/twitter-oauth-for-winjs
 * Copyright Manifold 2012. All rights reserved.
 * Apache License, Version 2.0
 */

//NOTE: This is a proof of concept and experiment, it's probably not a good idea to put secrets in code which will be dsitributes to machines you are not in control of
//http://stackoverflow.com/questions/18391058/how-safe-are-secret-keys-in-windows-8-winjs-apps
// http://stackoverflow.com/questions/7623335/how-do-i-protect-oauth-keys-from-a-user-decompiling-my-project

//Get these secrets by signing up for the Vimeo API
WinJS.Namespace.define("Vimeo.OAuth.Config", {
    consumerKey: '',//Client ID
    consumerSecret: '',//Client Secret
    userOAuthToken: '',//Access token
    userOAuthTokenSecret: '' //Access token secret
});


WinJS.Namespace.define("Vimeo.API.Config", {
    apiEndpoint: 'https://vimeo.com/api/rest/v2',
    outputFormat: 'json'
});