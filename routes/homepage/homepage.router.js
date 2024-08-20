const path = require('path')
const express = require('express');
const fs = require('fs');
const router = express.Router();
const openssl = require('openssl-nodejs');
const keccak256 = require('keccak256');

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

// hash function
var cryptoSuite = fabric_common.Utils.newCryptoSuite();
var hashFunction = cryptoSuite.hash.bind(cryptoSuite);

var caClient;
var registerChannel, estateRegisterInstance;
var entrustChannel, estateAgentInstance, leaseRegisterInstance;
var wallet;
var gateway;
var adminUser;

var addEstate = {};
var acceptEstate = {};
var rejectEstate = {};
var newLease = {};

const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection) {
    const HouseData = dbconnection.model('houseDatas', require('../../models/leaseSystem/houseData'));
    const Profile = dbconnection.model('profiles', require('../../models/leaseSystem/profile'));
    const Interest = dbconnection.model('interests', require('../../models/leaseSystem/interest'));

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
        await delay(2000);

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


        entrustChannel = await gateway.getNetwork('entrust-channel');
        estateAgentInstance = await entrustChannel.getContract('EstateAgent');
        leaseRegisterInstance = await entrustChannel.getContract('LeaseRegister');
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

    router.get('/profile', isAuthenticated, (req, res) => {
        const identity = req.session.address;
        Profile.findOne({ address: identity }).then((obj) => {
            res.render('leaseSystem/profile', { address: identity, user: obj });
        });
    });

    router.post('/profile/profileUpdate', isAuthenticated, async (req, res) => {
        const identity = req.session.address;
        const { name } = req.body;

        let obj = await Profile.findOneAndUpdate(
            { address: identity },
            { name: name }, { new: true }
        );
        // console.log(obj);
        if (!obj) {
            errors = "Save data error.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        res.render('leaseSystem/profile', { address: identity, user: obj });
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
                // console.log("first time login");
                let PIContractAddress = await identityManagerInstance.methods.getAccessManagerAddress(account).call({ from: account });
                let personalIdentityInstance = new web3.eth.Contract(personalIdentity.output.abi, PIContractAddress);

                let EncryptCSRHex = await personalIdentityInstance.methods.getEncryptMaterial("HLFCSR").call({ from: account });

                //If upgrading to the latest version does not fix the issue, try downgrading to a previous version of the ethers library. You can specify a version number when installing the ethers library using the npm package manager.

                let EncryptCSR = JSON.parse(ethers.utils.toUtf8String(EncryptCSRHex));
                let CSR = decrypt(EncryptCSR, privateKey);
                let CSRDecode = await opensslDecode(Buffer.from(CSR));
                // // Decode CSR to get CN and pubkey.
                const regex = /CN=([^\s]+)\s+/;
                // let CN = CSRDecode.match(regex);
                let CN = CSRDecode.substr(CSRDecode.indexOf('CN =') + 5, account.length);
                let start_index = '-----BEGIN PUBLIC KEY-----'.length
                let end_index = CSRDecode.indexOf('-----END PUBLIC KEY-----')
                let pubkey_base64 = CSRDecode.substring(start_index, end_index).replace(/\n/g, '');
                let pubkey_hex = Buffer.from(pubkey_base64, 'base64').toString('hex');
                pubkey_hex = pubkey_hex.substr('3059301306072a8648ce3d020106082a8648ce3d030107034200'.length)

                if (CN) {
                    try {
                        // first time login this appChain
                        let attrs = [
                            { name: 'category', value: 'client', ecert: true }
                        ]
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
                        console.log(error);
                        console.log('\x1b[33m%s\x1b[0m', `${CN} already register in ca`);
                        return res.send({ 'msg': 'create x509Identity error.' });
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
            const pubkey = req.user.pubkey;
            req.session.address = address;
            req.session.pubkey = pubkey;
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

    // HLF Transaction offline signing PART

    async function createTransaction() {
        // parameter 0 is user identity
        // parameter 1 is chaincode function Name
        // parameter 2 to end is chaincode function parameter
        var user = await buildCertUser(wallet, fabric_common, arguments[0]);
        var userContext = gateway.client.newIdentityContext(user);

        var endorsementStore;
        // console.log('arguments[1] = ' + arguments[1]);
        switch (arguments[1]) {
            case 'AddEstate':
                endorsementStore = addEstate;
                var endorsement = entrustChannel.channel.newEndorsement('EstateAgent');
                break;
            case 'AcceptEstate':
                endorsementStore = acceptEstate;
                var endorsement = entrustChannel.channel.newEndorsement('EstateAgent');
                break;
            case 'RejectEstate':
                endorsementStore = rejectEstate;
                var endorsement = entrustChannel.channel.newEndorsement('EstateAgent');
                break;
            case 'NewLease':
                endorsementStore = newLease;
                var endorsement = entrustChannel.channel.newEndorsement('LeaseRegister');
                break;
        }

        var paras = [];
        for (var i = 2; i < arguments.length; i++) {
            paras.push(arguments[i])
        }

        // Need to add other contract
        // var endorsement = entrustChannel.channel.newEndorsement('EstateAgent');
        var build_options = { fcn: arguments[1], args: paras, generateTransactionId: true };
        var proposalBytes = endorsement.build(userContext, build_options);
        const digest = hashFunction(proposalBytes);
        endorsementStore[arguments[0]] = endorsement;

        return new Promise(function (reslove, reject) {
            reslove(digest);
        })
    };

    async function proposalAndCreateCommit() {
        // parameter 0 is user identity
        // parameter 1 is chaincode function Name
        // parameter 2 is signature

        var endorsementStore;
        switch (arguments[1]) {
            case 'AddEstate':
                endorsementStore = addEstate;
                break;
            case 'AcceptEstate':
                endorsementStore = acceptEstate;
                break;
            case 'RejectEstate':
                endorsementStore = rejectEstate;
                break;
            case 'NewLease':
                endorsementStore = newLease;
                break;
        }
        if (typeof (endorsementStore) == "undefined") {
            return new Promise(function (reslove, reject) {
                reject({
                    'error': true,
                    'result': "func dosen't exist."
                });
            })
        }

        // console.log('endorsementStore = ' + JSON.stringify(endorsementStore[arguments[0]]));

        let endorsement = endorsementStore[arguments[0]];
        endorsement.sign(arguments[2]);
        // console.log(endorsement);
        let proposalResponses = await endorsement.send({ targets: entrustChannel.channel.getEndorsers() });
        // console.log(proposalResponses);
        // console.log('proposalResponses = ' + JSON.stringify(proposalResponses));
        // console.log('responses[0] = ' + JSON.stringify(proposalResponses.responses[0]));
        // console.log('proposalResponses.responses[0].response.status = ' + proposalResponses.responses[0].response.status);
        if (proposalResponses.error) {
            console.log(proposalResponses.error);
        }
        if (proposalResponses.responses[0].response.status == 200) {
            let user = await buildCertUser(wallet, fabric_common, arguments[0]);
            let userContext = gateway.client.newIdentityContext(user)

            let commit = endorsement.newCommit();
            let commitBytes = commit.build(userContext)
            let commitDigest = hashFunction(commitBytes)
            let result = proposalResponses.responses[0].response.payload.toString();
            endorsementStore[arguments[0]] = commit;

            return new Promise(function (reslove, reject) {
                reslove({
                    'commitDigest': commitDigest,
                    'result': result
                });
            })
        }
        else {
            return new Promise(function (reslove, reject) {
                reject({
                    'error': true,
                    'result': proposalResponses.responses[0].response.message
                });
            })
        }
    };

    async function commitSend() {
        // parameter 0 is user identity
        // parameter 1 is chaincode function Name
        // parameter 2 is signature

        var endorsementStore;
        switch (arguments[1]) {
            case 'AddEstate':
                endorsementStore = addEstate;
                break;
            case 'AcceptEstate':
                endorsementStore = acceptEstate;
                break;
            case 'RejectEstate':
                endorsementStore = rejectEstate;
                break;
            case 'NewLease':
                endorsementStore = newLease;
                break;
        }
        if (typeof (endorsementStore) == "undefined") {
            return new Promise(function (reslove, reject) {
                reject({
                    'error': true,
                    'result': "func doesn't exist."
                });
            })
        }
        let commit = endorsementStore[arguments[0]]
        commit.sign(arguments[2])
        let commitSendRequest = {};
        commitSendRequest.requestTimeout = 300000
        commitSendRequest.targets = entrustChannel.channel.getCommitters();
        let commitResponse = await commit.send(commitSendRequest);

        if (commitResponse['status'] == "SUCCESS") {
            return new Promise(function (reslove, reject) {
                reslove({
                    'result': true
                });
            })
        }
        else {
            return new Promise(function (reslove, reject) {
                reject({
                    'error': true,
                    'result': "commit error"
                });
            })
        }
    }

    function convertSignature(signature) {
        signature = signature.split("/");
        let signature_array = new Uint8Array(signature.length);
        for (var i = 0; i < signature.length; i++) {
            signature_array[i] = parseInt(signature[i])
        }
        let signature_buffer = Buffer.from(signature_array)
        return signature_buffer;
    }

    router.post("/proposalAndCreateCommit", isAuthenticated, async (req, res) => {
        try {
            let { signature, func } = req.body;

            let signature_buffer = convertSignature(signature)
            let response = await proposalAndCreateCommit(req.session.address, func, signature_buffer)
            // console.log(response);
            return res.send(response);

        } catch (error) {
            console.log(error);
            return res.send(error);
        }
    });

    router.post("/commitSend", isAuthenticated, async (req, res) => {
        try {
            let { signature, func, estateAddress, ownerAddress } = req.body;
            let signature_buffer = convertSignature(signature);
            let response = await commitSend(req.session.address, func, signature_buffer);
            // console.log(response);

            // change local database
            try {
                if (!response.error && func == "NewLease") {
                    // console.log("change DB state");
                    // console.log(req.session.address);
                    let obj = await HouseData.findOneAndUpdate({ ownerAddress: req.session.address, houseAddress: estateAddress }, { state: "online" });
                    // if (obj) {
                    //     // console.log(obj);
                    //     // console.log("update local data");
                    // }
                }
                else if (!response.error && func == "AcceptEstate") {
                    let obj = await HouseData.findOneAndUpdate({ houseAddress: ownerAddress }, { agent: req.session.address, state: "agent" });
                    if (obj) {
                        console.log(obj);
                        // console.log("update local data");
                    }
                }
            } catch (error) {
                console.log("local db update error");
            }

            return res.send(response);
        } catch (error) {
            console.log(error);
            return res.send(error);
        }
    })


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
        const { addr } = req.body;
        res.send({ url: 'estatePage?addr=' + addr });
    });

    router.get('/landlord/estatePage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: addr });
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
        res.render('leaseSystem/landlord/landlordAgnet', { address: address, HouseData: obj, agentList: obj2, contract_address: contract_address });
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
        res.render('leaseSystem/landlord/rent', { address: address, HouseData: obj, contract_address: contract_address });
    });


    router.post('/landlord/estateBind', isAuthenticated, async (req, res) => {
        // get chain data, then create a record in system DB
        const { userAddress, houseAddress } = req.body;

        // get user public key
        let dbPubkey = await Profile.findOne({ address: userAddress }, 'pubkey');
        let pubkey = dbPubkey.pubkey;

        // get chain data
        let obj2 = await estateRegisterInstance.evaluateTransaction('GetEstate', pubkey, houseAddress);
        let data;
        try {
            data = JSON.parse(obj2);
        } catch (error) {
            let errors = "The Real Estate data does not exists on blockchain.";
            return res.send({ msg: errors });
        }

        // check exist in local
        let obj = await HouseData.findOne({ ownerAddress: userAddress, houseAddress: data.address });
        if (obj) {
            let errors = "The estate data already exists in system.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        try {
            const houseData = new HouseData({
                ownerAddress: userAddress,
                houseAddress: data.address,
                area: data.area,
                state: "new",
                title: '',
                describe: ''
            })
            let en_str = userAddress.toString('hex') + data.address.toString('hex');
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

    router.post('/landlord/entrustSubmit', isAuthenticated, async (req, res) => {
        let { address, agentPubkey, estateAddress, ownerAddress, type } = req.body;
        let owner = await Profile.findOne({ address: ownerAddress });
        try {
            const digest = await createTransaction(address.toLowerCase(), 'AddEstate', agentPubkey, ownerAddress, owner.pubkey, estateAddress, type);
            return res.send({ 'digest': digest });
        } catch (e) {
            console.log('e = ' + e)
            return res.send({ 'error': "error", "result": e })
        }
    });

    router.post('/landlord/NewLease', isAuthenticated, async (req, res) => {
        let { address, estateAddress, rent, dataHash } = req.body;
        let owner = await Profile.findOne({ address: address });
        try {
            const digest = await createTransaction(address.toLowerCase(), 'NewLease', owner.pubkey, estateAddress, rent, dataHash);
            return res.send({ 'digest': digest });
        } catch (e) {
            console.log('e = ' + e)
            return res.send({ 'error': "error", "result": e })
        }
    });

    // Agent PART
    router.get('/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await Profile.findOne({ address: address });
        res.render('leaseSystem/agent/agent', { address: address, user: obj });
    });

    router.post('/agent/getCert', isAuthenticated, async (req, res) => {
        // check agent have a cert for agent on chain, and save to localDB
        // const { userAddress } = req.body;
        const userAddress = req.session.address;

        // get user public key
        let dbPubkey = await Profile.findOne({ address: userAddress }, 'pubkey');
        let pubkey = dbPubkey.pubkey;
        // console.log(pubkey);

        // get chain data

        try {
            let obj2 = await estateAgentInstance.evaluateTransaction('GetAgent', pubkey);
            let data = JSON.parse(obj2.toString());
        } catch (error) {
            console.log(error);

            let errors = "The agent data does not exists on chain.";
            console.log(errors);
            return res.send({ msg: errors });
        }
        // let obj2 = await estateAgentInstance.evaluateTransaction('GetAgent', pubkey);
        // let data = JSON.parse(obj2.toString());
        // // console.log(data);
        // if (!data) {
        //     let errors = "The agent data does not exists on chain.";
        //     console.log(errors);
        //     return res.send({ msg: errors });
        // }

        // save local
        let obj = await Profile.findOneAndUpdate(
            { address: userAddress },
            { agent: true }
        );
        // console.log(obj);
        if (!obj) {
            errors = "The agent data error in system.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        return res.send({ msg: "success" });
    });

    router.get('/agent/manageAgreement', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        // get user public key
        let dbPubkey = await Profile.findOne({ address: address }, 'pubkey');
        let pubkey = dbPubkey.pubkey;

        // get chain data
        let obj2 = await estateAgentInstance.evaluateTransaction('GetAgentEstate', pubkey);
        let data = {};
        try {
            data = JSON.parse(obj2.toString());
        } catch (error) { }

        let agreement = [];
        Object.keys(data).forEach(function (key) {
            if (data[key].state != "reject") {
                agreement.push(data[key]);
            }
        })

        res.render('leaseSystem/agent/manageAgreement', { address: address, agreement: agreement, 'contract_address': contract_address });
    });

    router.post('/agent/AcceptEstate', isAuthenticated, async (req, res) => {
        // const address = req.session.address;
        let { address, estateAddress } = req.body;
        let owner = await Profile.findOne({ address: address });
        try {
            const digest = await createTransaction(address.toLowerCase(), 'AcceptEstate', owner.pubkey, estateAddress);
            return res.send({ 'digest': digest });
        } catch (e) {
            console.log('e = ' + e)
            return res.send({ 'error': "error", "result": e })
        }
    });

    router.post('/agent/RejectEstate', isAuthenticated, async (req, res) => {
        // const address = req.session.address;
        let { address, estateAddress } = req.body;
        let owner = await Profile.findOne({ address: address });
        try {
            const digest = await createTransaction(address.toLowerCase(), 'RejectEstate', owner.pubkey, estateAddress);
            return res.send({ 'digest': digest });
        } catch (e) {
            console.log('e = ' + e)
            return res.send({ 'error': "error", "result": e })
        }
    });

    router.post('/agent/estatePage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        console.log(addr);

        // let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: req.body.addr });
        res.send({ url: 'estatePage?addr=' + addr });
    });

    router.get('/agent/estatePage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;

        let obj = await HouseData.findOne({ houseAddress: addr });
        res.render('leaseSystem/agent/agentEstatePage', { address: address, HouseData: obj });
    });

    router.post('/agent/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        // let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: req.body.addr });
        res.send({ url: 'rent?addr=' + addr });
    });

    router.get('/agent/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        let obj = await HouseData.findOne({ houseAddress: addr });
        res.render('leaseSystem/agent/agentRent', { address: address, HouseData: obj, contract_address: contract_address });
    });

    router.post('/agent/estateUpdate', isAuthenticated, async (req, res) => {
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

    router.post('/agent/profileUpdate', isAuthenticated, async (req, res) => {
        //  get local data, then update the record in system DB
        const { userAddress, name, Agency } = req.body;

        let obj = await Profile.findOneAndUpdate(
            { address: userAddress, agent: true },
            { name: name, agency: Agency }, { new: true }
        );
        console.log(obj);
        if (!obj) {
            errors = "The agent data error in system.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        res.render('leaseSystem/agent/agent', { address: userAddress, user: obj });
    });

    // Search lease PART
    router.get('/searchHouse', async (req, res) => {
        const address = req.session.address;
        let obj2 = await leaseRegisterInstance.evaluateTransaction('GetAllOnlineLease');
        let data = {};
        try {
            data = JSON.parse(obj2.toString());
        } catch (error) {
            console.log(error);
            data = obj2;
        }
        // console.log(obj2.toString());
        // let obj = await HouseData.find({ state: "online" });
        let houseList = [];
        for (let index = 0; index < data.length; index++) {
            // console.log(data[index].Data);
            Object.values(data[index].Data).forEach(value => {
                if (value.state == "online") {
                    // console.log(value);
                    houseList.push(value);
                }
            });
        }
        res.render('leaseSystem/searchHouse', { address: address, houseList: houseList });
    });

    router.post('/searchHouse/leasePage', async (req, res) => {
        const address = req.session.address;
        const { addr, uploader } = req.body;
        res.send({ url: 'leasePage?addr=' + addr + '&uploader=' + uploader });
    });


    router.get('/leasePage', async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        const uploader = req.query.uploader;

        let obj2 = await Profile.findOne({ pubkey: uploader });

        let obj = await HouseData.findOne({ ownerAddress: obj2.address, houseAddress: addr });

        let obj3 = await leaseRegisterInstance.evaluateTransaction('GetLease', uploader, addr);
        let data = {};
        try {
            data = JSON.parse(obj3.toString());
        } catch (error) {
            console.log(error);
            data = obj3;
        }
        res.render('leaseSystem/leasePage', { address: address, HouseData: obj, rentData: data, added: false });
    });

    router.post('/searchHouse/leasePage/add', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { houseAddress, uploaderAddress } = req.body;
        try {
            let obj = new Interest({
                address: address,
                ownerAddress: uploaderAddress,
                houseAddress: houseAddress,
                willingness: false,
                agreement: false
            })
            await obj.save();
            return res.send({ msg: "add favorite success" });
        } catch (error) {
            return res.send({ msg: "add favorite error" });
        }
    });

    router.post('/searchHouse/leasePage/remove', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { houseAddress, uploaderAddress } = req.body;
        try {
            let obj = await Interest.findOneAndDelete({
                address: address,
                ownerAddress: uploaderAddress,
                houseAddress: houseAddress
            })

            return res.send({ msg: "remove favorite success" });
        } catch (error) {
            return res.send({ msg: "remove favorite error" });
        }
    });

    router.post('/searchHouse/leasePage/newSigner', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { houseAddress, uploaderAddress } = req.body;
        try {
            let obj = await Interest.findOneAndUpdate({
                address: address,
                ownerAddress: uploaderAddress,
                houseAddress: houseAddress
            }, { willingness: true })

            return res.send({ msg: "update success, please waiting for owner create the agreement" });
        } catch (error) {
            return res.send({ msg: "update error" });
        }
    });

    // Agreement PART
    router.get('/leaseManage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let favoriteList = await Interest.find({ address: address });
        let signerList = await Interest.find({ ownerAddress: address, willingness: true });

        let key = await Profile.findOne({ address: address });
        let data = {};
        try {
            let obj3 = await leaseRegisterInstance.evaluateTransaction('GetPersonLease', key.pubkey);
            data = JSON.parse(obj3.toString());
        } catch (error) {
            // console.log(error);
            data = {};
        }
        let rentData = [];
        Object.keys(data).forEach(function (key) {
            rentData.push(data[key]);
        })


        res.render('leaseSystem/leaseManage', { address: address, favorite: favoriteList, signerList: signerList, rentData: rentData });
    });

    router.post('/leaseManage/leasePage', async (req, res) => {
        const address = req.session.address;
        const { addr, uploader } = req.body;
        res.send({ url: 'leaseManage/leasePage?addr=' + addr + '&uploader=' + uploader });
    });


    router.get('/leaseManage/leasePage', async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        const uploader = req.query.uploader;
        let obj2 = await Profile.findOne({ address: uploader });

        let obj = await HouseData.findOne({ ownerAddress: uploader, houseAddress: addr });

        let obj3 = await leaseRegisterInstance.evaluateTransaction('GetLease', obj2.pubkey, addr);
        let data = {};
        try {
            data = JSON.parse(obj3.toString());
        } catch (error) {
            console.log(error);
            data = obj3;
        }
        res.render('leaseSystem/leasePage', { address: address, HouseData: obj, rentData: data, added: true });
    });

    router.post('/leaseManage/agreementCreate', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { hashed, ownerAddress, houseAddress } = req.body;
        let obj = await HouseData.findOneAndUpdate({ ownerAddress: ownerAddress, houseAddress: houseAddress }, { rentHashed: hashed, state: "signing" });
        if (obj) {
            res.send({ msg: `success` });
        }
        else {
            res.send({ msg: `error` });
        }
    });

    router.post('/leaseManage/agreement', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { follower, estateAddress } = req.body;
        // let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: req.body.addr });
        res.send({ url: `leaseManage/agreement?f=${follower}&e=${estateAddress} ` });
    });

    router.get('/leaseManage/agreement', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const follower = req.query.f;
        const estateAddress = req.query.e;
        let houseData = await HouseData.findOne({ ownerAddress: address, houseAddress: estateAddress });
        let ownerData = await Profile.findOne({ address: address }, 'address pubkey');
        let tenant = await Profile.findOne({ address: follower }, 'address pubkey');
        let rentData = {};
        try {
            let obj3 = await leaseRegisterInstance.evaluateTransaction('GetLease', ownerData.pubkey, estateAddress);
            rentData = JSON.parse(obj3.toString());
        } catch (error) {
            console.log(error);
            rentData = {};
        }
        res.render('leaseSystem/agreement/agreement', {
            address: address,
            houseData: houseData, rentData: data,
            ownerData: ownerData, tenantData: tenant,
            contract_address: contract_address
        });
    });

    return router;
}