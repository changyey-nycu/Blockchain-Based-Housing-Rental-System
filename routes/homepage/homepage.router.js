const path = require('path')
const express = require('express');
const fs = require('fs');
const router = express.Router();
const openssl = require('openssl-nodejs');

// session
const passport = require('passport');
const LocalStrategy = require('passport-local');

const config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/IdentityManager.json', 'utf-8'));
const personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
const contract_address = config.contracts.identityManagerAddress;
const privateKey = config.leaseSystem.key;
const { Web3 } = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));

const { ethers } = require('ethers');
const { decrypt, encrypt } = require("eth-sig-util");

// HLF
const fabric_common = require("fabric-common");
const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const { buildCAClient, enrollAdmin, registerAndEnrollUser, getAdminIdentity, buildCertUser } = require('../../util/CAUtil');
const { buildCCPOrg2, buildWallet } = require('../../util/AppUtil');

var caClient;
var registerChannel, estateRegisterInstance, estateAgentInstance;
var wallet;
var gateway;
var adminUser;

const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection1, dbconnection2) {
    const HouseData = dbconnection1.model('houseDatas', require('../../models/leaseSystem/houseData'));
    const Profile = dbconnection1.model('profiles', require('../../models/leaseSystem/profile'));

    // for test
    const ChainRealEstate = dbconnection2.model('chainrealEstates', require('../../models/test/realEstate'));
    const ChainAgency = dbconnection2.model('agencies', require('../../models/test/agency'));
    const Chainlease = dbconnection2.model('leases', require('../../models/test/lease'));

    let delay = async (ms) => {
        return new Promise(resolve => setTimeout(resolve, ms))
    }

    async function opensslDecode(buffer_input) {
        return new Promise(function (reslove, reject) {
            openssl(['req', '-text', '-in', { name: 'key.csr', buffer: buffer_input }, '-pubkey'], function (err, result) {
                reslove(result.toString())
            })
        })
    }

    async function init() {
        //console.log('google router init()');
        await delay(1000);

        // build an in memory object with the network configuration (also known as a connection profile)
        const ccp = buildCCPOrg2();

        // build an instance of the fabric ca services client based on
        // the information in the network configuration
        caClient = buildCAClient(FabricCAServices, ccp, 'ca.org2.example.com');

        const walletPath = path.join(__dirname, '../../wallet/system');
        wallet = await buildWallet(Wallets, walletPath);

        mspOrg2 = 'Org2MSP';
        await enrollAdmin(caClient, wallet, mspOrg2);//remember to change ca url http to https

        //get ca admin to register and enroll user
        adminUser = await getAdminIdentity(caClient, wallet)

        // in a real application this would be done only when a new user was required to be added
        // and would be part of an administrative flow
        await registerAndEnrollUser(caClient, wallet, mspOrg2, 'system' /*, 'org2.department1'*/);


        // Create a new gateway instance for interacting with the fabric network.
        // In a real application this would be done as the backend server session is setup for
        // a user that has been verified.
        gateway = new Gateway();

        //console.log(JSON.stringify(gateway));
        await gateway.connect(ccp, {
            wallet,
            identity: 'system',
            discovery: { enabled: true, asLocalhost: true }
        });

        registerChannel = await gateway.getNetwork('register-channel');
        estateRegisterInstance = await registerChannel.getContract('EstateRegister');
        estateAgentInstance = await registerChannel.getContract('EstateAgent');
    }
    init();

    // Login PART

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
            if (req.hashed && req.pubkey) {
                // Mapping DB data: identity => address, pubkey => pubkey
                return done(null, { 'address': username.toLowerCase(), 'pubkey': req.pubkey });
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

    router.post('/loginWithMetamask', async (req, res, next) => {
        const address = req.body.account.toLowerCase();

        let { account, signature } = req.body;
        let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();


        if (signingAccount != account.toLowerCase()) {
            return res.send({ 'msg': 'Failed to verify signature' });
        }

        let { identity, userType } = req.body;   //DID  userType=>user: 0   org: 1


        let identityManagerInstance = new web3.eth.Contract(identityManager.output.abi, contract_address);


        if (identity) {
            // Verify from the database whether the user is logging in for the first time
            var pubkey;
            try {
                let result = await Profile.findOne({ address: account.toLowerCase() });
                pubkey = result.pubkey;
                // console.log(pubkey);
            } catch {
                pubkey = null;
            }

            //check is first time login?
            if (pubkey) {       //not first time
                req.hashed = identity;
                req.pubkey = pubkey;
                next();
            } else {            //first time login
                let PIContractAddress = await identityManagerInstance.methods.getAccessManagerAddress(account).call({ from: account });
                let personalIdentityInstance = new web3.eth.Contract(personalIdentity.output.abi, PIContractAddress);

                let EncryptCSRHex = await personalIdentityInstance.methods.getEncryptMaterial("HLFCSR").call({ from: account });

                //If upgrading to the latest version does not fix the issue, try downgrading to a previous version of the ethers library. You can specify a version number when installing the ethers library using the npm package manager.

                let EncryptCSR = JSON.parse(ethers.utils.toUtf8String(EncryptCSRHex));
                let CSR = decrypt(EncryptCSR, privateKey);
                let CSRDecode = await opensslDecode(Buffer.from(CSR));

                // // Decode CSR to get CN and pubkey.
                const regex = /CN=([^\s]+)\s+/;
                // let CN = CSRDecode.match(regex)[1];
                let CN = CSRDecode.substr(CSRDecode.indexOf('CN=') + 3, account.length);
                let start_index = '-----BEGIN PUBLIC KEY-----'.length
                let end_index = CSRDecode.indexOf('-----END PUBLIC KEY-----')
                let pubkey_base64 = CSRDecode.substring(start_index, end_index).replace(/\n/g, '');
                let pubkey_hex = Buffer.from(pubkey_base64, 'base64').toString('hex');
                pubkey_hex = pubkey_hex.substr('3059301306072a8648ce3d020106082a8648ce3d030107034200'.length)

                if (CN) {
                    try {
                        // first time login this appChain
                        let attrs = [
                            { name: 'category', ecert: true }
                        ]
                        //console.log(adminUser);
                        let secret = await caClient.register({
                            enrollmentID: CN,
                            role: 'client',
                            attrs: attrs
                        }, adminUser);

                        let enrollment = await caClient.enroll({
                            csr: CSR,
                            enrollmentID: CN,
                            enrollmentSecret: secret
                        });

                        const x509Identity = {
                            credentials: {
                                certificate: enrollment.certificate
                            },
                            mspId: mspOrg2,
                            type: 'X.509',
                        };
                        await wallet.put(address, x509Identity);
                        console.log('\x1b[33m%s\x1b[0m', "create x509 cert successfully.");
                    } catch (error) {
                        console.log('\x1b[33m%s\x1b[0m', `${CN} already register in ca`);
                    }

                    try {
                        const obj = new Profile({
                            address: account.toLowerCase(),
                            agent: false,
                            pubkey: pubkey_hex
                        })
                        obj.save();
                    } catch (error) {
                        console.log(error);
                        return res.send({ 'msg': 'create profile error.' });
                    }
                    req.hashed = identity;
                    req.pubkey = pubkey_hex;
                    next();
                } else {
                    console.log("CN and account are not match.")
                    return res.send({ 'msg': 'CN and account are not match.' });
                }
            }
        } else {
            return res.send({ 'msg': 'DID dose not exist.' });
        }
    },
        passport.authenticate('verifySign_LeaseSystem'),
        async function (req, res) {
            const address = req.user.address;
            req.session.address = address;
            res.send({ url: "/leaseSystem/profile" });
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

    // landlord PART
    router.get('/landlord', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/landlord', { address: address });
    });

    router.get('/landlord/upload', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/upload', { address: address });
    });

    router.get('/landlord/manageEstate', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await HouseData.find({ ownerAddress: address });
        res.render('leaseSystem/landlord/manageEstate', { address: address, HouseData: obj });
    });

    router.post('/landlord/estatePage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: req.body.addr });
        res.render('leaseSystem/landlord/estatePage', { address: address, HouseData: obj });
    });

    router.post('/landlord/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        res.send({ url: 'agent?addr=' + addr });
    });

    router.get('/landlord/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;

        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: addr });
        let obj2 = await Profile.find({ agent: true });
        res.render('leaseSystem/landlord/landlordAgnet', { address: address, HouseData: obj, agentList: obj2 });
    });

    router.post('/landlord/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        res.send({ url: 'rent?addr=' + addr });
    });


    router.get('/landlord/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: addr });
        res.render('leaseSystem/landlord/rent', { address: address, HouseData: obj });
    });


    router.post('/landlord/estateBind', isAuthenticated, async (req, res) => {
        // get chain data, then create a record in system DB
        const { userAddress, houseAddress } = req.body;

        // get chain data
        console.log("get chain data");
        let obj2 = await estateRegisterInstance.evaluateTransaction('GetEstate', userAddress, houseAddress);
        // let obj2 = await ChainRealEstate.findOne({ ownerAddress: userAddress, houseAddress: houseAddress });
        console.log(obj2);
        if (!obj2) {
            let errors = "The Real Estate data does not exists on chain.";
            console.log(errors);
            return res.send({ msg: errors });
        }


        // check exist in local
        let obj = await HouseData.findOne({ ownerAddress: obj2.ownerAddress, houseAddress: obj2.houseAddress });
        if (obj) {
            let errors = "The estate data already exists in system.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        try {
            const houseData = new HouseData({
                ownerAddress: obj2.ownerAddress,
                houseAddress: obj2.houseAddress,
                area: obj2.area,
                date: obj2.date,
                title: '',
                describe: ''
            })
            let en_str = obj2.ownerAddress.toString('hex') + obj2.houseAddress.toString('hex');
            let hashed = keccak256(en_str).toString('hex');
            houseData.hashed = hashed;
            await houseData.save();
        } catch (error) {
            console.log(error);
            return res.send({ msg: "save data error." });
        }

        console.log("save to system DB success");

        return res.send({ msg: "upload success." })
    });

    router.post('/landlord/estateUpdate', isAuthenticated, async (req, res) => {
        //  get local data, then update the record in system DB
        const { userAddress, houseAddress, title, roomType, describe } = req.body;
        if (describe.toString().length > 300) {
            return res.send({ msg: "describe too long" });
        }

        try {
            await HouseData.updateOne(
                { ownerAddress: userAddress, houseAddress: houseAddress },
                { title: title, type: roomType, describe: describe }
            )
        } catch (error) {
            console.log(error);
        }
        let obj = await HouseData.find({ ownerAddress: userAddress });
        return res.render('leaseSystem/landlord/manageEstate', { address: userAddress, HouseData: obj });
    });

    // Agent PART

    // Agreement PART
    router.get('/leaseManage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/leaseManage', { address: address });
    });

    // Other PART
    router.get('/searchHouse', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/searchHouse', { address: address });
    });


    

    return router;
}