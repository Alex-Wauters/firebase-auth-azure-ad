import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as jwt from 'jsonwebtoken';
import * as rp from 'request-promise';
import { isArray } from 'util';

const cors = require('cors')({ origin: true });

// Minting a Firebase Auth token requires manual wiring of the service account
const serviceAccount = require("../serviceAccountKey.json");
admin.initializeApp({
    databaseURL: JSON.parse(process.env.FIREBASE_CONFIG).databaseURL,
    credential: admin.credential.cert(serviceAccount)
});

let keys: Array<MSOpenIdKey> = [];

exports.validateAuth = functions.https.onRequest(async (req, res) => {

    cors(req, res, async () => {
        if (req.query && req.query.error) {
            console.error(`Authentication request error from Azure AD: ${req.query.error_description}. Full details: ${JSON.stringify(req.query)}`);
            res.status(400).send(`Oh oh, something went wrong. Please contact support with the following message: Invalid authentication request: ${req.query.error_description}`);
            return;
        }

        if (req.body && req.body.id_token) {
            try {
                const token = req.body.id_token;
                const unverified: any = jwt.decode(token, { complete: true });
                if (!unverified || !unverified.payload || unverified.payload.iss !== "https://sts.windows.net/YOUR_STS_IDENTIFIER/") { //TODO: Insert your STS GUID identifier
                    console.error(`Invalid unverified token (iss): ${token}. Unverified decoding: ${unverified}`);
                    throw new Error("Invalid issuer");
                }
                if (!unverified.header || unverified.header.alg !== "RS256" || !unverified.header.kid) {
                    throw new Error(`Invalid header or algorithm on token: ${token}`);
                }
                const k = await addSignatureKeysIfMissing();
                const signatureKey = k.find((c => {
                    return c.kid === unverified.header.kid;
                }));
                if (!signatureKey) {
                    throw new Error(`Signature used in token ${token} is not in the list of recognized keys: ${JSON.stringify(k)}`);
                }
                const upn = await verifyToken(token, signatureKey.x5c[0]);
                const customToken = await admin.auth().createCustomToken(upn);
                res.redirect(`/?jwt=${customToken}`);
            } catch (err) {
                console.error(`Failed to create custom token: ${err}`);
                res.status(400).send(`Oh oh, something went wrong. Please contact support with the following message: see the logs for more information.`);
            }
        } else {
            console.error(`No id_token present in request body`);
            res.status(400).send(`Oh oh, something went wrong. Please contact support with the following message: No token present in id_token attribute.`);
        }
    });
});

interface MSOpenIdKey {
    kty: string;
    use: string;
    kid: string;
    x5t: string;
    n: string;
    e: string;
    x5c: Array<string>;
    issuer: string;
}

function addSignatureKeysIfMissing(): Promise<Array<MSOpenIdKey>> {
    if (keys.length !== 0) {
        return Promise.resolve(keys);
    } else {
        return rp({ uri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys', json: true })
            .then((data) => {
                if (data && data.keys && isArray(data.keys) && data.keys.length > 0) {
                    keys = data.keys;
                    return keys;
                } else {
                    console.error(`Received from MS openID endpoint: ${data}`);
                    throw new Error("Could not read the keys from MS' openID discovery endpoint");
                }
            })
    }
}

async function verifyToken(token: string, cert: string): Promise<string> {
    return new Promise((resolve, reject) => {
        console.log(`Selected signature key: ${cert}`);
        jwt.verify(token, convertCertificate(cert), {
            algorithms: ["RS256"], // Prevent the 'none' alg from being used
            issuer: "https://sts.windows.net/YOUR_STS_IDENTIFIER/" //TODO: Insert your STS GUID identifier
        }, function (err, decoded: any) {
            if (err || !decoded) {
                console.error(`Could not verify token: ${err}`);
                reject(err);
            } else {
                const userId = decoded.upn || decoded.unique_name;
                if (!userId) {
                    console.error(`Could not find userId: ${JSON.stringify(decoded)}`);
                    reject("Could not find a userId in the response token");
                }
                console.info(`logged-in user: ${userId}`);
                resolve(userId);
            }
        })
    }) as Promise<string>;
}

//Certificate must be in this specific format or else jwt's verify function won't accept it
function convertCertificate(originalCert: string) {
    const beginCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";
    let cert = originalCert.replace("\n", "");
    cert = cert.replace(beginCert, "");
    cert = cert.replace(endCert, "");

    let result = beginCert;
    while (cert.length > 0) {

        if (cert.length > 64) {
            result += "\n" + cert.substring(0, 64);
            cert = cert.substring(64, cert.length);
        }
        else {
            result += "\n" + cert;
            cert = "";
        }
    }
    if (result[result.length] !== "\n")
        result += "\n";
    result += endCert + "\n";
    return result;
}