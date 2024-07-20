const express = require('express');
const fs = require('fs');
const router = express.Router();

// session
const passport = require('passport');
const LocalStrategy = require('passport-local');

const config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const contract_address = config.contracts.identityManagerAddress;
const { Web3 } = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));

// HLF
/*const fabric_common = require("fabric-common");
const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const { buildCAClient, enrollAdmin, registerAndEnrollUser, getAdminIdentity, buildCertUser } = require('../../util/CAUtil');
const { buildCCPOrg1, buildWallet } = require('../../util/AppUtil'); */


const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection) {
    // const houseData = dbconnection.model('houseData', require('../../models/leaseSystem/houseData'));
    const Profile = dbconnection.model('profiles', require('../../models/leaseSystem/profile'));

    var isAuthenticated = function (req, res, next) {
        // console.log('isAuthenticated : ' + req.isAuthenticated());
        if (req.isAuthenticated()) {
            next();
        } else {
            req.flash('info', 'Login first.');
            res.redirect('/LeaseSystem/login');
        }
    };

    passport.use('verifySign_LeaseSystem', new LocalStrategy({
        usernameField: 'account',
        passwordField: 'signature',
        passReqToCallback: true
    },
        async function (req, username, password, done) {
            let account = username.toLowerCase(); //address
            let signature = password;
            signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();

            if (signingAccount == account) {
                return done(null, { "address": account });
            }
            else {
                return done(null, false);
            }
        }
    ));

    router.get('/', (req, res) => {
        const identity = req.session.address;
        res.render('leaseSystem/homepage', { address: identity });
    });

    router.get('/homepage', (req, res) => {
        const identity = req.session.address;
        res.render('leaseSystem/homepage', { address: identity });
    });

    router.get('/profile', (req, res) => {
        const identity = req.session.address;
        Profile.findOne({ address: identity }).then((obj) => {
            if (!obj) {
                console.log("new user");
                let obj2 = new Profile({
                    address: identity,
                    agent: false
                })
                obj2.save();
                obj = obj2;
            }
            res.render('leaseSystem/profile', { address: identity, user: obj });
        });
    });

    router.get('/login', (req, res) => {
        req.session.destroy();
        res.render('leaseSystem/login', { 'require_signature': require_signature, 'contract_address': contract_address });
    });

    router.post('/loginWithMetamask', passport.authenticate('verifySign_LeaseSystem', {
        failureRedirect: '/leaseSystem'
    }), async function (req, res) {
        const address = req.user.address;
        req.session.address = address;
        res.send({ 'url': '/leaseSystem/profile' });
    });

    // router.post('/loginWithMetamask', async (req, res, next) => {
    //     const address = req.body.account.toLowerCase();

    //     let { account, signature } = req.body;
    //     let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();


    //     if (signingAccount != account.toLowerCase()) {
    //         return res.send({ 'msg': 'Failed to verify signature' });
    //     }

    //     let { identity, userType } = req.body;   //DID  userType=>user: 0   org: 1


    //     let identityManagerInstance = new web3.eth.Contract(identityManager.abi, contract_address);


    //     if (identity) {
    //         // Verify from the database whether the user is logging in for the first time
    //         var pubkey;
    //         try {
    //             let result = await Mapping.findOne({ address: account.toLowerCase() });
    //             pubkey = result.pubkey;
    //             //console.log(pubkey);
    //         } catch {
    //             pubkey = null;
    //         }

    //         //check is first time login?
    //         if (pubkey) {       //not first time
    //             req.hashed = identity;
    //             req.pubkey = pubkey;
    //             req.userType = userType;
    //             next();
    //         } else {            //first time login
    //             let PIContractAddress = await identityManagerInstance.methods.getAccessManagerAddress(account).call({ from: account });
    //             let personalIdentityInstance = new web3.eth.Contract(personalIdentity.abi, PIContractAddress);

    //             let EncryptCSRHex = await personalIdentityInstance.methods.getEncryptMaterial("HLFCSR").call({ from: account });

    //             //If upgrading to the latest version does not fix the issue, try downgrading to a previous version of the ethers library. You can specify a version number when installing the ethers library using the npm package manager.

    //             let EncryptCSR = JSON.parse(ethers.utils.toUtf8String(EncryptCSRHex));
    //             let CSR = decrypt(EncryptCSR, privateKey);
    //             let CSRDecode = await opensslDecode(Buffer.from(CSR));

    //             // // Decode CSR to get CN and pubkey.
    //             const regex = /CN=([^\s]+)\s+/;
    //             let CN = CSRDecode.match(regex)[1];
    //             //let CN = CSRDecode.substr(CSRDecode.indexOf('CN=') + 3, account.length);
    //             let start_index = '-----BEGIN PUBLIC KEY-----'.length
    //             let end_index = CSRDecode.indexOf('-----END PUBLIC KEY-----')
    //             let pubkey_base64 = CSRDecode.substring(start_index, end_index).replace(/\n/g, '');
    //             let pubkey_hex = Buffer.from(pubkey_base64, 'base64').toString('hex');
    //             pubkey_hex = pubkey_hex.substr('3059301306072a8648ce3d020106082a8648ce3d030107034200'.length)


    //             if (CN) {
    //                 try {
    //                     // first time login this appChain
    //                     let attrs = [
    //                         { name: 'category', value: 'dataProvider', ecert: true }
    //                     ]
    //                     //console.log(adminUser);
    //                     let secret = await caClient.register({
    //                         enrollmentID: CN,
    //                         role: 'client',
    //                         attrs: attrs
    //                     }, adminUser);

    //                     let enrollment = await caClient.enroll({
    //                         csr: CSR,
    //                         enrollmentID: CN,
    //                         enrollmentSecret: secret
    //                     });

    //                     const x509Identity = {
    //                         credentials: {
    //                             certificate: enrollment.certificate
    //                         },
    //                         mspId: mspOrg1,
    //                         type: 'X.509',
    //                     };
    //                     await wallet.put(address, x509Identity);
    //                     console.log('\x1b[33m%s\x1b[0m', "create x509 cert successfully.");
    //                 } catch (error) {
    //                     console.log('\x1b[33m%s\x1b[0m', `${CN} already register in ca`);
    //                 }
    //                 try {
    //                     // console.log(pubkey_hex);

    //                     var result = await accInstance.submitTransaction('AddPersonalAccessControl', pubkey_hex);
    //                     console.log('\x1b[33m%s\x1b[0m', result.toString());

    //                     console.log('transaction finish');

    //                     const mapping = new Mapping({ address: account.toLowerCase(), pubkey: pubkey_hex });
    //                     await mapping.save();
    //                     req.hashed = DID;
    //                     req.pubkey = pubkey_hex;
    //                     next();
    //                 }
    //                 catch (e) {
    //                     return res.send({ 'msg': 'create acc error.' });
    //                 }
    //             } else {
    //                 console.log("CN and account are not match.")
    //                 return res.send({ 'msg': 'CN and account are not match.' });
    //             }
    //         }
    //     } else {
    //         return res.send({ 'msg': 'DID dose not exist.' });
    //     }
    // },
    //     passport.authenticate('local'),
    //     async function (req, res) {
    //         res.send({ url: "/appChain/DataBroker/profile" });
    //     });

    router.get('/searchHouse', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/searchHouse', { address: address });
    });


    router.get('/leaseManage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/leaseManage', { address: address });
    });

    router.get('/logout', (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/leaseSystem/homepage');
            }
        });
    });

    return router;
}