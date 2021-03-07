//
// Create a JWT or decode and optionally verify it using a public key
//
// Currently only support RSA-SHA256 and RSA-SHA512 which are the most commonly used signatures
//
const argv = require('minimist')(process.argv.slice(2));
crypto = require('crypto');

let secondsOffset = 60;

function base64urlEncode(data) {
    const str = typeof data === 'number' ? data.toString() : data;
    return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64urlUnescape(str) {
    str += new Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function decodeJwt(jwtFile, publicKeyFile, forceAlg) {
    const fs = require('fs');

    try {
        var publicKeyString = fs.readFileSync(publicKeyFile, 'utf-8', 'r+');
    } catch (err) {
        console.error(`Failed to open key file: ${publicKeyFile}`);
        process.exit(2);
    }

    try {
        var jwt = fs.readFileSync(jwtFile, 'utf-8', 'r+');
    } catch (err) {
        console.error(`Failed to open JWT file: ${jwtFile}`);
        process.exit(3);
    }

    console.log(jwt);
    const [headerStr, payloadStr, signature] = jwt.split('.');
    //console.log(header, payload, signature);
    const header = JSON.parse(Buffer.from(base64urlUnescape(headerStr), 'base64'));
    const payload = JSON.parse(Buffer.from(base64urlUnescape(payloadStr), 'base64'));
    console.log(header, payload);

    var publicKey = crypto.createPublicKey(
        {
            key: publicKeyString,
            format: 'pem',

        }
    );

    const verification = crypto
        .createVerify(forceAlg ? forceAlg : (header.alg === 'RS256' ? 'RSA-SHA256' : 'RSA-SHA512'))
        .update(`${headerStr}.${payloadStr}`)
        .verify(publicKey, signature, 'base64');

    console.log(`\nSignature Verified: ${verification}`);
}

//console.log(argv);

if ((!argv.alg || !argv.sub || !argv.aud || !argv.iss) && (!argv.jwtfile || !argv.publickey)) {
    console.error('usage: node app.js [--alg=[RSA-SHA256 | RSA-SHA512] [--privatekey=filename --dumpkeys] [--ttl=expirationSeconds] --sub=SUBJECT --aud=AUDIENCE --iss=ISSUER] | [--jwtfile=filname --publickey=filename --forcealg=[RSA-SHA256 | RSA-SHA512]]');
    process.exit(1);
}

if (argv.jwtfile) {
    decodeJwt(argv.jwtfile, argv.publickey, argv.forcealg);
    process.exit(0);
}

if (argv.ttl) {
    secondsOffset = parseInt(argv.ttl);
}

if (!argv.privatekey) {

    var { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: argv.alg === 'RSA-SHA256' ? 2048 : 4096,
    })

    if (argv.dumpkeys) {
        console.log('publicKey:\n', publicKey.export({
            type: 'pkcs1',
            format: 'pem'
        }));
        console.log('privateKey:\n', privateKey.export({
            type: 'pkcs1',
            format: 'pem'
        }));
    }
} else {
    // Load private key from file
    const fs = require('fs');
    const privateKeyString = fs.readFileSync(argv.privatekey, 'utf-8', 'r+');
    //console.log(privateKeyString);

    var privateKey = crypto.createPrivateKey(
        {
            key: privateKeyString,
            format: 'pem',

        }
    );
}

const header = {
    "alg": argv.alg === 'RSA-SHA256' ? "RS256" : "RS512",
    "typ": "JWT"
}

const payload = {
    "sub": argv.sub,
    "aud": argv.aud,
    "iss": argv.iss,
    "exp": Math.floor((new Date()).getTime() / 1000) + secondsOffset,
    "iat": Math.floor((new Date()).getTime() / 1000)
}

const strHeader = JSON.stringify(header);
const b64Header = base64urlEncode(strHeader);

const strPayload = JSON.stringify(payload);
const b64Payload = base64urlEncode(strPayload);

const sign = crypto
    .createSign(argv.alg)
    .update(`${b64Header}.${b64Payload}`)
    .sign(privateKey);

const jwt = `${b64Header}.${b64Payload}` + '.' + base64urlEncode(sign);

console.log('jwt:\n' + jwt);

