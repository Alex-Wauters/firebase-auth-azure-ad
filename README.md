
# Introduction

This repository describes an authentication flow for Firebase Auth and Azure Ad (OpenId Connect). It has been based on the [Azure AD OpenId Connect guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code). It's different from usual OpenId authentication scenarios as Firebase uses Functions as a Service.

A more detailed guide is available at https://medium.com/@alex.wauters/how-to-integrate-a-firebase-web-app-with-azure-active-directory-b5c0f01a0c24 

Please note, this code has been used for an application with a low risk footprint and the flow below has not been penetration tested or audited. If you would like to use this flow for your Firebase app and the risk of a breach on the app is not acceptable, be sure to request an audit. Please let me know in case you discover any issues.

Alternatives such as SaaS Identity Providers like Auth0 offer integrations with Azure AD and Firebase, but are costly.

Performance wise you can make an improvement by retrieving the signing certificates of the Azure AD STS on a daily basis or when the certificates are about to renew, instead of doing it for each authentication request.


# Authentication Flow

I have used this authentication flow for Firebase Auth with Vue (see `main.js`), but you may use any front-end library.

Upon entering the front-end app, Firebase will validate whether the user is authenticated.
If the user is not authenticated, the front-end app will attempt to retrieve a custom `jwt` token from the browser's location href.

If it's not present, the front-end will redirect the browser to Azure Ad with an Authentication Request. The redirectUrl is assigned to the validateAuth function, through a rewrite rule in firebase.json:

````
"hosting": {
     "public": "public",
     "ignore": [
       "firebase.json",
       "**/.*",
       "**/node_modules/**"
     ],
     "rewrites": [ {
       "source": "/auth", "function": "validateAuth"
     } ]
   },

````

The user authenticates to AzureAd, and the authentication response is sent to firebaseapp/auth, which triggers the validateAuth function.

ValidateAuth will retrieve the valid signing certificates from your tenant and validate 
* whether the issuer of the authentication response is your tenant
* whether a signing algorithm was used, and if it matches one of the signing certificates associated with your tenant

If that checks out, the function will mint a firebase authentication token for your firebase app. To send the token to your front-end app, it will redirect the browser to the firebaseapp and include the `jwt` parameter along with the token.

The flow is back to where we began, and the custom token is sent to the firebase auth service for validation. The user is now authenticated. In your app, you can remove the jwt parameter from the location href manually.

# STS Entity Id and Application ID
The authentication functions verify whether the issuer is the STS associated with your tenant. Don't forget to insert the EntityId (GUID) of your STS as well as the application client ID of your app in the constants at top of `index.ts`

You may find the EntityId in [the federation metadata](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-federation-metadata).

