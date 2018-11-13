/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , url = require('url')
  , querystring= require('querystring')
  , crypto = require('crypto')
  , jws = require('jws')
  , base64url = require('base64url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , InternalOAuthError = require('./errors/internaloautherror')
  , path = require('path')
  , https= require('https')
  , URL = require('url')
  , fs = require('fs');

function OAuth2Extension (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  OAuth2.call(this, clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders);
}

util.inherits(OAuth2Extension, OAuth2);

OAuth2Extension.prototype.getOAuthAccessToken = function(code, params, certs, callback) {
	  
  var params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= querystring.stringify( params );
  var post_headers= {
       'Content-Type': 'application/x-www-form-urlencoded'
  };

  this._request("POST", OAuth2Extension.super_.prototype._getAccessTokenUrl.call(this), post_headers, post_data, null, certs, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring.parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
}

OAuth2Extension.prototype._request = function(method, url, headers, post_body, access_token, certs, callback) {

  var parsedUrl= URL.parse( url, true );
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
    parsedUrl.port= 443;
  }

  var http_library= this._chooseHttpLibrary( parsedUrl );

  var realHeaders= {};
  for( var key in this._customHeaders ) {
    realHeaders[key]= this._customHeaders[key];
  }
  if( headers ) {
    for(var key in headers) {
      realHeaders[key] = headers[key];
    }
  }
  realHeaders['Host']= parsedUrl.host;

  if (!realHeaders['User-Agent']) {
    realHeaders['User-Agent'] = 'Node-oauth';
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          realHeaders["Content-Length"]= post_body.length;
      } else {
          realHeaders["Content-Length"]= Buffer.byteLength(post_body);
      }
  } else {
      realHeaders["Content-length"]= 0;
  }

  if( access_token && !('Authorization' in realHeaders)) {
    if( ! parsedUrl.query ) parsedUrl.query= {};
    parsedUrl.query[this._accessTokenName]= access_token;
  }

  var queryStr= querystring.stringify(parsedUrl.query);
  if(queryStr) queryStr=  "?" + queryStr;

  var options = {
    host:parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname + queryStr,
    method: method,
    headers: realHeaders
  };
  
  if (certs) {
	  options.ca = certs;
  }

  OAuth2Extension.super_.prototype._executeRequest.call(this, http_library, options, post_body, callback);
}

function Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'openidconnect';
  this._verify = verify;
  
  if (!options.authorizationURL) throw new Error('OpenIDConnectStrategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OpenIDConnectStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OpenIDConnectStrategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OpenIDConnectStrategy requires a clientSecret option');

  this._authorizationURL = options.authorizationURL;
  this._tokenURL = options.tokenURL;
  this._userInfoURL = options.userInfoURL;
  this._issuer = options.issuer;
  
  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
  this._callbackURL = options.callbackURL;
  
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  this._HSAlg = ['HS256', 'HS384', 'HS512'];
  this._RSAlg = ['RS256', 'RS384', 'RS512'];
  this._ESAlg = ['ES256', 'ES384', 'ES512'];
  
  if (options.addCACert) {
	    
    this._certs = []

    if (!options.CACertPathList)  throw new Error('Please include an array of the CA certs to be used.');
    if (!util.isArray(options.CACertPathList)) throw new Error('Please set the CA cert path list to be in an array format.');

    var startPath = path.resolve(__dirname, '..', '..', '..');

    for(var i = 0; i < options.CACertPathList.length; i++) {
      var filepath = startPath + options.CACertPathList[i];

      if(filepath[0] === '/')
         var root = '/';
      else
         var root = '';
	      
      var pathlist = filepath.split(/\//g);
      pathlist.unshift(root);

      filepath = path.join.apply(null, pathlist);

      var content = fs.readFileSync(filepath); 
      this._certs.push(content);
    }

  }
  else {
    this._certs = null;
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Verify the Issuer Identifier in the ID Token
 *
 * @param {Object} jwtClaims
 * @return boolean
 */
Strategy.prototype.verifyIssuer = function (jwtClaims) {
  return (this._issuer === jwtClaims.iss);
};

Strategy.prototype.returnError = function (ErrMessage) {

  var ErrorObject = new Error(ErrMessage);
  Error.captureStackTrace(ErrorObject, arguments.callee);
  console.error(ErrorObject.stack);

  Error.stackTraceLimit = 0;
  ErrorObject = new Error(ErrMessage);
  Error.stackTraceLimit = 10;
        
  return ErrorObject;
};

Strategy.prototype.returnInternalOAuthError = function (ErrMessage, err) {
  
  var ErrorObject = new InternalOAuthError(ErrMessage, err);
  Error.captureStackTrace(ErrorObject, arguments.callee);
  console.error(ErrorObject.stack);

  Error.stackTraceLimit = 0;
  ErrorObject = new InternalOAuthError(ErrMessage, err);
  Error.stackTraceLimit = 10;
        
  return ErrorObject; 
};

/**
 * Verify the Authorized Party in the ID Token
 * Need to check that the Authorized Party property exists first
 * before calling this function
 *
 * @param {Object} jwtClaims
 * @return boolean
 */
Strategy.prototype.verifyAzp = function (jwtClaims) {
  return (this._clientID === jwtClaims.azp);
};

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  
  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
	
    return this.fail();
  }
  
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }
  
  
  if (req.query && req.query.code) {
    var code = req.query.code;
    
    var oauth2 = new OAuth2Extension(this._clientID,  this._clientSecret,
                            '', this._authorizationURL, this._tokenURL);

    oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, self._certs, function(err, accessToken, refreshToken, params) {
      if (err) {
        return self.error(self.returnInternalOAuthError('failed to obtain access token', err));
      }
            
      var idToken = params['id_token'];
      if (!idToken) {
        return self.error(self.returnError('ID Token not present in token response'));
      }
      
      var idTokenSegments = idToken.split('.')
        , jwtClaimsStr
        , jwtClaims
        , idHeader;
      
      try {
        idHeader = JSON.parse(new Buffer(idTokenSegments[0], 'base64'));
        jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
        jwtClaims = JSON.parse(jwtClaimsStr);
      } catch (ex) {
        return self.error(ex);
      }
      
      var iss = jwtClaims.iss;
      var sub = jwtClaims.sub;
      // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
      // "sub" claim was named "user_id".  Many providers still issue the
      // claim under the old field, so fallback to that.
      if (!sub) {
        sub = jwtClaims.user_id;
      }

      if(idHeader.alg) {
        if(self._HSAlg.indexOf(idHeader.alg) > -1) {
          if(!Array.isArray(jwtClaims.aud) || (Array.isArray(jwtClaims.aud) && jwtClaims.aud.length === 1)) {
            if(!jwtClaims.azp || (jwtClaims.azp && jwtClaims.azp === jwtClaims.aud) || (jwtClaims.azp && jwtClaims.azp === jwtClaims.aud[0])) {

              var isValid = jws.verify(idToken, idHeader.alg, self._clientSecret);

              if(!isValid) {
                return self.error(self.returnError('Token is invalid. Validation failed.'));
              }
            }
            else return self.error(self.returnError('Token is invalid. Authorized Party does not match with Audience.'));
          }
          else return self.error(self.returnError('Token is invalid. Invalid Audience.'));
        }
        else if(self._RSAlg.indexOf(idHeader.alg) > -1 || self._ESAlg.indexOf(idHeader.alg) > -1) {

          var isValid = false;

          if(self._certs === null || self._certs.length === 0) {
            return self.error(self.returnError('Certificate(s) are not provided. Validation failed.'));
          }

          for(var i = 0; i < self._certs.length; i++) {
            if(jws.verify(idToken, idHeader.alg, self._certs[i]))
              isValid = true;
          }

          if(!isValid) {
            return self.error(self.returnError('Invalid certificate(s).'));
          }
        }
        else return self.error(self.returnError('Invalid algorithm.'));
      }

      if(!iss || !sub || !jwtClaims.aud || !jwtClaims.exp || !jwtClaims.iat) { 
          return self.error(self.returnError('Missing required claim(s).'));
      }

      // Decoding and verifying. If any of the verification fails, ID Token must be rejected.

      // Verifying Issuer
      if(!(self.verifyIssuer(jwtClaims))) {
        return self.error(self.returnError('Mismatched Issuer.'));
      }

      // Verifying Authorized Party (AZP)
      if(jwtClaims.azp) {
        if(!(self.verifyAzp(jwtClaims))) {
          return self.error(self.returnError('Mismatched Authorized Party.'));
        }
      }

      // Verifying the Audience (AUD)
      if(Array.isArray(jwtClaims.aud)) {
        var audLength = jwtClaims.aud.length;
        if(audLength === 0) {
          return self.error(self.returnError('Audience is empty.'));
        }
        else if(audLength > 1) {
          if(jwtClaims.azp) {

            // TODO: Need to check if array contains client ID. If not, reject.
            // Also need to check if there's any untrusted audiences. If so, reject.
            // As of now, client only trusts itself as an audience and nothing else.
            // This is due to each login having only one client, and thus only one audience.

            return self.error(self.returnError('Audience may not have more than one entry.'));
          }
          else {
            return self.error(self.returnError('Authorized Party is required.'));
          }
        }
        else {
          if(self._clientID !== jwtClaims.aud[0]) {
            return self.error(self.returnError('Mismatched Client Id.'));
          }
        }

      }
      else {
        if(self._clientID !== jwtClaims.aud) {
          return self.error(self.returnError('Mismatched Client Id.'));
        }
      }

      // Verifying Expired Time (EXP) time
      var currTime = Math.round(new Date().getTime()/1000.0);
      if(currTime >= jwtClaims.exp) {
        return self.error(self.returnError('Current time (' + currTime + ') is past ID Token Expired Time Claim (' + jwtClaims.exp + ').'));
      }

      // Verifying Issued At Time (IAT) time

      // TODO: Checks to see if IAT is too long and should be considered expired.


      // Verify Access Token (if at_hash is provided)
      if(jwtClaims.at_hash) {
        if(idHeader.alg) {

          if(self._HSAlg.indexOf(idHeader.alg) === -1 && self._RSAlg.indexOf(idHeader.alg) === -1 && self._ESAlg.indexOf(idHeader.alg) === -1) {
            return self.error(self.returnError('Unsupported Algorithm.'));
          }

          var atHash;
          var hash;
          var halfHash;
            
          if(idHeader.alg.indexOf('256') > -1) {hash = crypto.createHash('sha256').update(accessToken).digest('hex');}
          else if(idHeader.alg.indexOf('384') > -1) {hash = crypto.createHash('sha384').update(accessToken).digest('hex');}
          else {hash = crypto.createHash('sha512').update(accessToken).digest('hex');}


          halfHash = hash.slice(0, (hash.length)/2.0);
          var base64Ver = new Buffer(halfHash, 'hex').toString('base64');
          atHash = base64url.fromBase64(base64Ver);

          if(atHash !== jwtClaims.at_hash) {
            return self.error(self.returnError('Mismatched Hashes.'));
          }
        }
        else {
          return self.error(self.returnError('Unspecified Algorithm.'));
        }
      }


      self._shouldLoadUserProfile(iss, sub, function(err, load) {
        if (err) { return self.error(err); };
        
        if (load) {
          var parsed = url.parse(self._userInfoURL, true);
          //parsed.query['schema'] = 'openid';
          //delete parsed.search;
          var userInfoURL = url.format(parsed);
                    
          // NOTE: We are calling node-oauth's internal `_request` function (as
          //       opposed to `get`) in order to send the access token in the
          //       `Authorization` header rather than as a query parameter.
          //
          //       Additionally, the master branch of node-oauth (as of
          //       2013-02-16) will include the access token in *both* headers
          //       and query parameters, which is a violation of the spec.
          //       Setting the fifth argument of `_request` to `null` works
          //       around this issue.
          
          //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
          oauth2._request("GET", userInfoURL, { 'Authorization': "Bearer " + accessToken, 'Accept': "application/json" }, null, null, self._certs, function (err, body, res) {
            if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }
                        
            var profile = {};
            
            try {
              var json = JSON.parse(body);
              
              profile.id = json.sub;
              // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
              // "sub" key was named "user_id".  Many providers still use the old
              // key, so fallback to that.
              if (!profile.id) {
                profile.id = json.user_id;
              }
              
              profile.displayName = json.name;
              profile.name = { familyName: json.family_name,
                               givenName: json.given_name,
                               middleName: json.middle_name };
              
              profile._raw = body;
              profile._json = json;
              
              onProfileLoaded(profile);
            } catch(e) {
              return self.error(ex);
            }
          });
        } else {
	  //get profile info from id token
	  var profile = {};
	  profile.id = jwtClaims.sub;
	  // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
          // "sub" key was named "user_id".  Many providers still use the old
          // key, so fallback to that.
          if (!profile.id) {
            profile.id = jwtClaims.user_id;
          }

	  profile.displayName = jwtClaims.name;
	  if(jwtClaims.ext) {
		  var ext = JSON.parse(jwtClaims.ext);
		  for (var key in ext) {
			if(ext.hasOwnProperty(key)) {
				profile[key] = ext[key];
			}
		  }  
	  }

	  profile._json = jwtClaims;
	  
          onProfileLoaded(profile);
        }
        
        function onProfileLoaded(profile) {
          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }
        
          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 9) {
              self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity == 8) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity == 7) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity == 5) {
              self._verify(req, iss, sub, profile, verified);
            } else { // arity == 4
              self._verify(req, iss, sub, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 8) {
              self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity == 7) {
              self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity == 6) {
              self._verify(iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity == 4) {
              self._verify(iss, sub, profile, verified);
            } else { // arity == 3
              self._verify(iss, sub, verified);
            }
          }
        }
      });
    });
  } else {
    var params = this.authorizationParams(options);
    var params = {};
    params['response_type'] = 'code';
    params['client_id'] = this._clientID;
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
    if (scope) {
      params.scope = 'openid' + this._scopeSeparator + scope;
    } else {
      params.scope = 'openid';
    }
    // TODO: Add support for automatically generating a random state for verification.
    var state = options.state;
    if (state) { params.state = state; }
    // TODO: Implement support for standard OpenID Connect params (display, prompt, etc.)
    
    var location = this._authorizationURL + '?' + querystring.stringify(params);
    this.redirect(location);
  }
}

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
}

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return done(null, true); }
      return done(null, false);
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
    if (!skip) { return done(null, true); }
    return done(null, false);
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
