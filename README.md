passport-idaas-openidconnect
---

This module provides the passport strategy for authenticating specifically with the Bluemix Single Sign-On service.

Install
---
You may install the package using npm install command:

`npm install passport-idaas-openidconnect`

WARNING: Versions below 2.0.0 are deprecated due to security updates. Please use version 2.0.0 or higher. 

Uninstall
---
To uninstall passport-idaas-openidconnect from your system, use the npm uninstall command:

`npm uninstall passport-idaas-openidconnect`

Or just delete the passport-idaas-openidconnect directory.

Change History
---
* 1.1.0
  - Updated OAuth Dependency version to 0.9.13
  - Extended new configuration option: Including Local Certs
* 1.1.1
  - Patched Contributor + License in README
* 1.1.2
  - Local Cert option fixed
* 2.0.0
  - SECURITY UPDATE: Updated JWS dependency version to 3.1.0
  - Text messages changed for errors.
* 2.0.1
  - README UPDATE: New requirements for RS/ES signed JWT tokens

Usage
---
### Example
Below is a simple example of what is used to configure and use the strategy.

Note: `https://myapp.mybluemix.net/auth/sso/callback` is a sample callback url.

```javascript
var services = JSON.parse(process.env.VCAP_SERVICES || "{}");
var ssoConfig = services.SingleSignOn[0]; 
var client_id = ssoConfig.credentials.clientId;
var client_secret = ssoConfig.credentials.secret;
var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
var token_url = ssoConfig.credentials.tokenEndpointUrl;
var issuer_id = ssoConfig.credentials.issuerIdentifier;
var callback_url = 'https://myapp.mybluemix.net/auth/sso/callback';

var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;
var Strategy = new OpenIDConnectStrategy({
                authorizationURL : authorization_url,
                tokenURL : token_url,
                clientID : client_id,
                scope : 'email',
                response_type : 'code',
                clientSecret : client_secret,
                callbackURL : callback_url,
                skipUserProfile : true,
                issuer : issuer_id},
      function(iss, sub, profile, accessToken, refreshToken, params, done) {
        process.nextTick(function() {
            profile.accessToken = accessToken;
            profile.refreshToken = refreshToken;
            done(null, profile);
        })
      }
})

passport.use(Strategy); 

app.get('/auth/sso/callback',function(req,res,next) {
    var redirect_url = req.session.originalUrl;
        passport.authenticate('openidconnect', {
                successRedirect: redirect_url,
                failureRedirect: '/failure',
        })(req,res,next);
    });

app.get('/failure', function(req, res) { 
             res.send('login failed'); });

app.get('/login', passport.authenticate('openidconnect', {})); 

function ensureAuthenticated(req, res, next) {
  if(!req.isAuthenticated()) {
              req.session.originalUrl = req.originalUrl;
    res.redirect('/login');
  } else {
    return next();
  }
}

app.get('/hello', ensureAuthenticated, function(req, res) {
             res.send('Hello, '+ req.user['id'] + '!');
           });
```

### Configure Strategy
The strategy authenticates users using the Bluemix Single Sign-On service, which includes various credentials required by the strategy, most of which are already provided by the service. Included are the client id, client secret, authorization endpoint, token endpoint, and the issuer id.

```javascript
var services = JSON.parse(process.env.VCAP_SERVICES || "{}");
var ssoConfig = services.SingleSignOn[0]; 
var client_id = ssoConfig.credentials.clientId;
var client_secret = ssoConfig.credentials.secret;
var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
var token_url = ssoConfig.credentials.tokenEndpointUrl;
var issuer_id = ssoConfig.credentials.issuerIdentifier;
var callback_url = PUT_CALLBACK_URL_HERE;

var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;
var Strategy = new OpenIDConnectStrategy({
                authorizationURL : authorization_url,
                tokenURL : token_url,
                clientID : client_id,
                scope : 'email',
                response_type : 'code',
                clientSecret : client_secret,
                callbackURL : callback_url,
                skipUserProfile : true,
                issuer : issuer_id},
      // This is the verify callback
      function(iss, sub, profile, accessToken, refreshToken, params, done) {
        process.nextTick(function() {
            profile.accessToken = accessToken;
            profile.refreshToken = refreshToken;
            done(null, profile);
        })
      }
})

passport.use(Strategy);
```

### Including Local Certificates
From version 1.1.0 to 1.1.2, there is an additional option in the strategy configuration, namely using specified local certificates. This option is not required.

As of version 2.0.0, this option is only optional for JSON Web Tokens signed with HMAC (HS) based algorithms specified in the JWS module. JWTs signed with RSASSA (RS) and ECDSA (ES) based algorithms will require the PEM encoded public key/signing certificate. This can be done by enabling this option and adding the said signing certificate as a local certificate, as explained below.

You can configure the strategy to specify one or more local certificates that you want to use when requesting the access token, and subsequently the ID token.  To specify a local certificate:
a. Set the attribute addCAcert to true.   By default, the attribute is false.
b. Set the attribute CACertPathList to provide a path list to your certificates.  Note that if addCAcert is false, CACertPathList is ignored.

For example:

```javascript
...
issuer: issuer_id,
addCACert: true,
CACertPathList: [‘/example.crt’, ‘/example2.cer’]},
...
```

Include your certificates in the application directory hierarchy so that they can be read when the strategy is created. When listing your certificates, specify the location relative to the application directory.  For example, if your certificate example1.crt is in the application directory, list it as ‘/example1.crt’. If it is located within a subdirectory of the application directory, such as  ssl, list it as ‘/ssl/example1.crt’


### Callback URL
The callback URL is a requirement for the strategy.

The callback URL is the URL for the application that consumes the authentication tokens and retrieves the user profile. For example: `https://myapp.mybluemix.net/auth/sso/callback`

Code for the callback function is also required to specify what the app does after a user logs in. Using the example mentioned above, if the callback URL is `https://myapp.mybluemix.net/auth/sso/callback`, ensure that the callback URI you specify for `app.get` is `auth/sso/callback`.

The path to the resource that was originally requested is stored in the `req.session.originalUrl` property. 

The following example shows a callback function that redirects users to the page they originally requested before they logged in. If the login fails, users are directed to the `/failure` page.

```javascript
app.get('/auth/sso/callback',function(req,res,next) {
    var redirect_url = req.session.originalUrl;
        passport.authenticate('openidconnect', {
                successRedirect: redirect_url,
                failureRedirect: '/failure',
        })(req,res,next);
    });

app.get('/failure', function(req, res) { 
             res.send('login failed'); });
```

### Verify Callback
The strategy requires a verify callback, which accepts various types of parameters.

By default, these are possible parameters for the verify callback:

* `function (iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done)`
* `function (iss, sub, profile, accessToken, refreshToken, params, done)`
* `function (iss, sub, profile, accessToken, refreshToken, done)`
* `function (iss, sub, profile, done)`
* `function (iss, sub, done)`

There is an optional attribute called `passReqToCallback` that can be added to the strategy in order to pass the request to the verify callback. This can be done by adding it in the strategy:

```javascript
...
skipUserProfile : true,
issuer : issuer_id,
passReqToCallback : true},
...
```

Doing so will result in the same types of callbacks listed above, except each callback will be appended with the request in front:

* `function (req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done)`
* `function (req, iss, sub, profile, accessToken, refreshToken, params, done)`
* `function (req, iss, sub, profile, accessToken, refreshToken, done)`
* `function (req, iss, sub, profile, done)`
* `function (req, iss, sub, done)`

### `ensureAuthenticated()` and `/login` route

The `ensureAuthenticated()` method and `/login` route are also required in the app.

`ensureAuthenticated()` checks if the user is already authenticated. If not, the method then stores the current url as the original url that calls the authentication request. It then redirects to the `/login` route, which will then start the authentication process using the configured strategy.

```javascript
app.get('/login', passport.authenticate('openidconnect', {})); 

function ensureAuthenticated(req, res, next) {
  if(!req.isAuthenticated()) {
      req.session.originalUrl = req.originalUrl;
      res.redirect('/login');
  } else {
    return next();
  }
}
```

To use `ensureAuthenticated()`, please include the method in the route to your app, such as the following test example:

```javascript
app.get('/hello', ensureAuthenticated, function(req, res) {
             res.send('Hello, '+ req.user['id'] + '!');
           });
```

### Test Sample

Note: Be sure that your Bluemix SSO service has been properly set up.

To test to make sure your app works properly with the Bluemix Single Sign-On service, include the following code in your app:

```javascript
app.get('/hello', ensureAuthenticated, function(req, res) {
             res.send('Hello, '+ req.user['id'] + '!');
           });
```

After including this code, try going to the `/hello` route for your app after it has been successfully deployed to Bluemix.

For example: `https://myapp.mybluemix.net/hello`


Contact Email
---
Please use this email for contact if you have questions: Security_SSO_Operations@wwpdl.vnet.ibm.com

Contributors
---
* Jared Hanson (http://www.jaredhanson.net/)
* Ciaran Jessup
* IBM

License
---
MIT License

Copyright (c) 2013 Jared Hanson

Copyright (c) 2010-2012 Ciaran Jessup

Copyright (c) 2015 IBM

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.