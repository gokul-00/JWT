const express = require('express')
const base64 = require('base64url');
const crypto = require('crypto');
const fs = require('fs');

//express app init
const app = express()

// view engine
app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))

//generating public and private keys
function genKeyPair() {
    
    const keyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096, 
        publicKeyEncoding: {
            type: 'pkcs1', 
            format: 'pem' 
        },
        privateKeyEncoding: {
            type: 'pkcs1', 
            format: 'pem' 
        }
    });
    fs.writeFileSync(__dirname + '/publicKey.pem', keyPair.publicKey); 
    fs.writeFileSync(__dirname + '/privateKey.pem', keyPair.privateKey);
}

// header object
const headerObj = {
    alg: 'RS256', // algorithm
    typ: 'JWT' 
};

let token = '', verify;

app.get('/',(req,res) => {
    verify = undefined
    res.render('index',{token:token,verify:verify})
})

app.post('/add/user',async (req,res) => {
    const payloadObj = {
        name: req.body.name,
        password: req.body.password,
        secret: req.body.secret
    };

    try {
    await genKeyPair()
    const signatureFunction = crypto.createSign('RSA-SHA256');
    const headerObjString = JSON.stringify(headerObj);
    const payloadObjString = JSON.stringify(payloadObj);
    
    const base64UrlHeader = base64(headerObjString);
    const base64UrlPayload = base64(payloadObjString);
    
    signatureFunction.write(base64UrlHeader + '.' + base64UrlPayload);
    signatureFunction.end();
    
    const PRIV_KEY = fs.readFileSync(__dirname + '/privateKey.pem', 'utf8');
    
    const signatureBase64 = signatureFunction.sign(PRIV_KEY, 'base64');
    const signatureBase64Url = base64.fromBase64(signatureBase64);
    
    token = base64UrlHeader + '.' + base64UrlPayload + '.' + signatureBase64Url 
    res.redirect('/')
    } catch (error) {
        console.log(error)
        res.redirect('/')
    }  
})

app.post('/user/verify',async (req,res) => {

    try {
        let JWT = await req.body.jwt
        const verifyFunction = crypto.createVerify('RSA-SHA256');
        const PUB_KEY = fs.readFileSync(__dirname + '/publicKey.pem', 'utf8');
        const jwtHeader = JWT.split('.')[0];
        const jwtPayload = JWT.split('.')[1];
        const jwtSignature = JWT.split('.')[2];
    
        verifyFunction.write(jwtHeader + '.' + jwtPayload);
        verifyFunction.end();
    
        const jwtSignatureBase64 = base64.toBase64(jwtSignature);
        const signatureIsValid = verifyFunction.verify(PUB_KEY, jwtSignatureBase64, 'base64');
    
        
        verify = signatureIsValid
        console.log(verify)
        res.render('index',{token:token,verify:verify})
    } catch (error) {
        console.log(error)
        res.redirect('/')
    }


})

const PORT = process.env.PORT || 3000

app.listen(PORT,()=>console.log(`server running on PORT : ${PORT}`))