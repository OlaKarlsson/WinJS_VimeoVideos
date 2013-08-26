/**
 * WinJS_VimeoVideo
 * By Ola Karlsson
 * http://olakarlsson.com
 * Based on WinJS OAuth for Twitter v1.3
 * https://github.com/cauld/twitter-oauth-for-winjs
 * Copyright Manifold 2012. All rights reserved.
 * Apache License, Version 2.0
 */

var VimeoOAuth = WinJS.Class.define(
    //Constructor
    function (consumerKey, consumerSecret, accessToken, accessTokenSecret, callbackUrl) {
        this._consumerKey = consumerKey;
        this._consumerSecret = consumerSecret;

        //If we already have accessToken then the part of getting the token is not needed
        this._accessToken = accessToken || null;
        this._accessTokenSecret = accessTokenSecret || null;

        //Define the OAuth callback url, not normally important for desktop apps
        this._callbackURL = callbackUrl || '';
    },
    {
            _xhrRequest: function (method, url, postBody, authzHeader, callback) {
                var request;

                try {
                    request = new XMLHttpRequest();
                    request.open(method, url, true);
                    request.onreadystatechange = function () {
                        if (request.readyState === 4) {
                            if (request.status === 200) {
                                callback(request.responseText, 200);
                            } else {
                                callback(false, request.status);
                            }
                        }
                    };
                    request.setRequestHeader("Authorization", authzHeader);

                    if (method === 'GET' || postBody === null) {
                        request.send();
                    } else {
                        request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                        request.setRequestHeader("Content-length", postBody.length);
                        request.send(postBody);
                    }
                } catch (err) {
                    //console.log("Error sending request: " + err);
                    callback(false, 500);
                }
            },
            

            //Generate an OAuth 1.0a HMAC-SHA1 signature for an HTTP request
                _generateHmacSha1Signature: function (sigBaseString, keyText) {
                    var keyMaterial,
                        macAlgorithmProvider,
                        tbs,
                        key,
                        signatureBuffer,
                        signature;

                    keyMaterial = Windows.Security.Cryptography.CryptographicBuffer.convertStringToBinary(keyText, Windows.Security.Cryptography.BinaryStringEncoding.Utf8);
                    macAlgorithmProvider = Windows.Security.Cryptography.Core.MacAlgorithmProvider.openAlgorithm("HMAC_SHA1");
                    key = macAlgorithmProvider.createKey(keyMaterial);
                    tbs = Windows.Security.Cryptography.CryptographicBuffer.convertStringToBinary(sigBaseString, Windows.Security.Cryptography.BinaryStringEncoding.Utf8);
                    signatureBuffer = Windows.Security.Cryptography.Core.CryptographicEngine.sign(key, tbs);
                    signature = Windows.Security.Cryptography.CryptographicBuffer.encodeToBase64String(signatureBuffer);

                    return signature;
                },
                _getSortedKeys: function (obj) {
                    var key,
                        keys = [];

                    for (key in obj) {
                        if (obj.hasOwnProperty(key)) {
                            keys[keys.length] = key;
                        }
                    }

                    return keys.sort();
                },

    /** 
        * Assembles proper headers based on a series of provided tokens, secrets, and signatures
        */
        _getOAuthRequestHeaders: function (headerParams) {
            var i,
                k,
                kv,
                sortedKeys,
                sigParams,
                sigBaseString,
                sigBaseStringParams = '',
                queryParamsKey,
                keyText,
                signature,
                headers,
                timestamp = Math.round(new Date().getTime() / 1000.0),
                nonce = Math.random();

            // Acquiring a request token
            nonce = Math.floor(nonce * 1000000000);

            sigParams = {
                oauth_consumer_key: headerParams.consumerKey,
                oauth_nonce: nonce,
                oauth_signature_method: 'HMAC-SHA1',
                oauth_timestamp: timestamp,
                oauth_token: headerParams.oauthToken,
                oauth_version: '1.0'
            };

            //We need to combine the oauth params with any query params
            if (headerParams.queryParams) {
                for (queryParamsKey in headerParams.queryParams) {
                    if (headerParams.queryParams.hasOwnProperty(queryParamsKey)) {
                        sigParams[queryParamsKey] = headerParams.queryParams[queryParamsKey];
                    }
                }
            }

            // Compute base signature string and sign it.
            // This is a common operation that is required for all requests even after the token is obtained.
            // Parameters need to be sorted in alphabetical order
            // Keys and values should be URL Encoded.
            sortedKeys = this._getSortedKeys(sigParams);
            for (i = 0; i < sortedKeys.length; i++) {
                k = sortedKeys[i];
                kv = sigParams[sortedKeys[i]];
                if (kv && kv !== '') {
                    if (sigBaseStringParams !== '') {
                        sigBaseStringParams += '&';
                    }
                    sigBaseStringParams += k + '=' + kv;
                }
            }

            sigBaseString = headerParams.method + "&" + encodeURIComponent(headerParams.url) + "&" + encodeURIComponent(sigBaseStringParams);

            keyText = encodeURIComponent(headerParams.consumerSecret) + "&";
            if (headerParams.oauthTokenSecret) {
                keyText += encodeURIComponent(headerParams.oauthTokenSecret);
            }

            signature = this._generateHmacSha1Signature(sigBaseString, keyText);
            headers = "OAuth " +
                "oauth_consumer_key=\"" + headerParams.consumerKey +
                "\", oauth_nonce=\"" + nonce +
                "\", oauth_signature=\"" + encodeURIComponent(signature) +
                "\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + timestamp +
                (headerParams.oauthToken ? ("\", oauth_token=\"" + headerParams.oauthToken) : "") +
                "\", oauth_version=\"1.0\"";

           
            return headers;
        },




        //Signs a request with the apps consumer secret & the users access token secret
        //Note: queryParms must be an object with key/value pairs (values should be urlencoded)
        sendAuthorizedRequestForUser: function (url, method, queryParams) {
            var self = this,
                promise,
                postBody = null,
                headerParams,
                authzHeader;

            promise = new WinJS.Promise(function (complete) {
                headerParams = {
                    consumerKey: self._consumerKey,
                    consumerSecret: self._consumerSecret,
                    oauthToken: self._accessToken,
                    oauthTokenSecret: self._accessTokenSecret,
                    url: url,
                    method: method
                };

                if (queryParams) {
                    headerParams.queryParams = queryParams;

                    var i = 0,
                        key,
                        queryString = '';

                    for (key in queryParams) {
                        if (queryParams.hasOwnProperty(key)) {
                            if (i > 0) {
                                queryString += '&';
                            }
                            queryString += key + '=' + queryParams[key];
                            i++;
                        }
                    }

                    if (method === 'GET') {
                        url += '?' + queryString;
                    } else {
                        postBody = queryString;
                    }
                }

                authzHeader = self._getOAuthRequestHeaders(headerParams);
                self._xhrRequest(method, url, postBody, authzHeader, function (results, statusCode) {
                    complete({
                        results: results,
                        statusCode: statusCode
                    });
                });
            });

            return promise;
        }
    },
    //staticMembers
    {}
);

var VimeoVideo = WinJS.Class.define(
    //Constructor
    function(vimeoVideoObj) {
        this.id = vimeoVideoObj.id;
        this.title = vimeoVideoObj.title;
        this.thumbnail = vimeoVideoObj.thumbnails.thumbnail[2];//to get different size, do a find replace and swap _640 for maybe _295
        this.description = vimeoVideoObj.description;
        this.duration = vimeoVideoObj.duration;
        this.tags = vimeoVideoObj.tags;
        this.dateUploaded = vimeoVideoObj.upload_date;
        this.videoUrl = vimeoVideoObj.urls.url[0]._content;
        this.userName = vimeoVideoObj.owner.display_name;
        this.linkToUser = vimeoVideoObj.owner.profileurl;
        this.videoSource = 'vimeo';

    },
    //Instance members
    {
        id: '',
        title:'',
        thumbnail: '',
        description: '',
        duration: '',
        tags: [],
        dateUploaded: '',
        videoUrl: '',
        userName: '',
        linkToUser: ''
    },
    //Static members
    {
        videoOrigin: 'vimeo'
    }
    );

//default for page in the API is 1 and max/default per page is 50
    function getVimeoGroupVideos(vimeoOAuthInstance, groupId, optionalParameters, callback) {
       
        //If no parameters, create object
        optionalParameters = optionalParameters || {};
        optionalParameters.page = optionalParameters.page || '1';
        optionalParameters.perPage = optionalParameters.perPage || '50';
        optionalParameters.summaryResponse = optionalParameters.summaryResponse || '1';
        optionalParameters.fullResponse = optionalParameters.fullResponse || '1';


        var queryParams,
            url = Vimeo.API.Config.apiEndpoint;
        
        queryParams = {
            'format': Vimeo.API.Config.outputFormat,
            'method': 'vimeo.groups.getVideos',
            'group_id': groupId,
            'page': optionalParameters.page,
            'per_page': optionalParameters.perPage,
            'summary_response': optionalParameters.summaryResponse,
            'full_response': optionalParameters.fullResponse
        };

        vimeoOAuthInstance.sendAuthorizedRequestForUser(url, 'GET', queryParams)
           .then(function (response) {
               callback(response.results);
           })
           .done();
    }

    function createVideoFromVimeo(item) {
        var vimeoVideo = new VimeoApi.VimeoVideo(item);
        return vimeoVideo;
    }

//TODO: Make a get all videos method that checks the total number of videos and keeps calling incrementing the page number

    WinJS.Namespace.define("VimeoApi", {
        getVimeoGroupVideos: getVimeoGroupVideos,
        createVideoFromVimeo: createVideoFromVimeo,
        VimeoVideo: VimeoVideo,
        VimeoOAuth: VimeoOAuth
    });
