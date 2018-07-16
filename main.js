/**
 * Following file is a snippet from Vue + Vuefire to redirect to the authentication functions.
 * You can combine the function from index.ts with any front-end library.
 */

firebase.auth().onAuthStateChanged(function (user) {
    if (user) {
        console.log('User is logged in');
        startApp();
    } else {
        const url = window.location.href;
        if (url.indexOf('jwt=') > -1) {  // The minted firebase token from Auth function
            const token = url.substr( url.indexOf('jwt=') + 4);
            console.log(token);
            firebase.auth().signInWithCustomToken(token)
                .then((user) => {
                    console.log(user);
                    window.location.href="/";
                })
                .catch(function (error) {
                    // Handle Errors here.
                    var errorCode = error.code;
                    var errorMessage = error.message;
                    console.error(errorCode + ' ' + errorMessage);
                });
        } else { // User not authenticated and no custom token present. Redirect to Azure AD for authentication token
            let redirectUrl = "https://login.microsoftonline.com/YOURTENANTNAME.onmicrosoft.com/oauth2/authorize?client_id=APPCLIENTID&&response_type=id_token&scope=openid&nonce=42&response_mode=form_post"; //TODO: Replace YOURTENANTNAME and APPCLIENTID
            if (window.location.port === "5000") { // Adjust the requested redirectUri for local development
                redirectUrl = redirectUrl + "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fauth";
            }
            window.location.href = redirectUrl;
        }
    }
});

function startApp() {
    /* eslint-disable no-new */
    new Vue({
        el: '#app',
        template: '<App/>',
        components: {App}
    })
}
