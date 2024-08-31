// gov use, to cert user estate and agent
const path = require('path')
const express = require('express');
const fs = require('fs');
const router = express.Router();

// session
const passport = require('passport');
const LocalStrategy = require('passport-local');

const config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const contract_address = config.contracts.identityManagerAddress;
const identityManger = JSON.parse(fs.readFileSync('./contracts/identityChain/IdentityManager.json', 'utf-8'));
const { Web3 } = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));
const keccak256 = require('keccak256');
const mongoose = require('mongoose');

//fabric SDK and Util
const fabric_common = require("fabric-common");
const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const { buildCAClient, enrollAdmin, registerAndEnrollUser, getAdminIdentity, buildCertUser } = require('../../util/CAUtil');
const { buildCCPOrg4, buildWallet } = require('../../util/AppUtil');

const require_signature = "LeaseSystem?nonce:778";

var caClient;
var accChannel, accInstance;
var wallet;
var gateway;
var adminUser;

var updatePermission = {};
var revokePermission = {};



module.exports = function (dbconnection) {
    const PersonalData = dbconnection.model('personalDatas', require('../../models/dataSharing/personalData'));

    let delay = async (ms) => {
        return new Promise(resolve => setTimeout(resolve, ms))
    }

    async function init() {
        //console.log('google router init()');
        await delay(4000);

        // build an in memory object with the network configuration (also known as a connection profile)
        const ccp = buildCCPOrg4();

        // build an instance of the fabric ca services client based on
        // the information in the network configuration
        caClient = buildCAClient(FabricCAServices, ccp, 'ca.org4.example.com');

        const walletPath = path.join(__dirname, '../../wallet/sharing');
        wallet = await buildWallet(Wallets, walletPath);

        mspOrg4 = 'Org4MSP';
        await enrollAdmin(caClient, wallet, mspOrg4);//remember to change ca url http to https

        //get ca admin to register and enroll user
        adminUser = await getAdminIdentity(caClient, wallet)

        // in a real application this would be done only when a new user was required to be added
        // and would be part of an administrative flow
        await registerAndEnrollUser(caClient, wallet, mspOrg4, 'sharing' /*, 'org1.department1'*/);


        // Create a new gateway instance for interacting with the fabric network.
        // In a real application this would be done as the backend server session is setup for
        // a user that has been verified.
        gateway = new Gateway();

        //console.log(JSON.stringify(gateway));
        await gateway.connect(ccp, {
            wallet,
            identity: 'sharing',
            discovery: { enabled: true, asLocalhost: true }
        });

        accChannel = await gateway.getNetwork('acc-channel');
        accInstance = await accChannel.getContract('AccessControlManager');
    }

    init();

    var isAuthenticated = function (req, res, next) {
        // console.log('isAuthenticated : ' + req.isAuthenticated());
        if (req.isAuthenticated()) {
            next();
        } else {
            req.flash('info', 'Login first.');
            res.redirect('/LeaseSystem/login');
        }
    };

    async function createTransaction() {
        // parameter 0 is user identity
        // parameter 1 is chaincode function Name
        // parameter 2 to end is chaincode function parameter
        var user = await buildCertUser(wallet, fabric_common, arguments[0]);
        var userContext = gateway.client.newIdentityContext(user);

        var endorsementStore;
        // console.log('arguments[1] = ' + arguments[1]);
        switch (arguments[1]) {
            case 'UpdatePermission':
                endorsementStore = updatePermission;
                break;
            case 'RevokePermission':
                endorsementStore = revokePermission;
                break;
        }

        var paras = [];
        for (var i = 2; i < arguments.length; i++) {
            paras.push(arguments[i])
        }

        // Need to add other contract
        var endorsement = accChannel.channel.newEndorsement('AccessControlManager');
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
            case 'UpdatePermission':
                endorsementStore = updatePermission;
                break;
            case 'RevokePermission':
                endorsementStore = revokePermission;
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
        let proposalResponses = await endorsement.send({ targets: accChannel.channel.getEndorsers() });
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
            case 'UpdatePermission':
                endorsementStore = updatePermission;
                break;
            case 'RevokePermission':
                endorsementStore = revokePermission;
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
        commitSendRequest.targets = accChannel.channel.getCommitters();
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
            let { signature, func } = req.body;
            let signature_buffer = convertSignature(signature);
            let response = await commitSend(req.session.address, func, signature_buffer);
            // console.log(response);

            return res.send(response);
        } catch (error) {
            console.log(error);
            return res.send(error);
        }
    })

    // router.post('/upload', isAuthenticated, async (req, res) => {
    //     const address = req.session.address;
    //     const pubkey = req.session.pubkey;
    //     const { ownerAddress, ownerPubkey, houseAddress } = req.body;
    //     res.send({ url: 'dataSharing/upload?owner=' + ownerAddress + '&house=' + houseAddress + '&key=' + ownerPubkey });
    // });

    router.get('/upload', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const owner = req.query.owner;
        const house = req.query.house;
        const key = req.query.key;
        let localData;
        try {
            localData = await PersonalData.findOne({ address: address });
            if (!localData) {
                localData = new PersonalData({ address: address, pubkey: pubkey });
                localData.save();
            }
        } catch (error) {
            console.log(error);
        }
        // console.log(localData);

        res.render('leaseSystem/dataSharing/upload', {
            address: address, pubkey: pubkey, owner: owner, ownerPubkey: key
            , house: house, tenantData: localData, contract_address: contract_address
        });
    });

    router.post('/request', isAuthenticated, async (req, res) => {
        // const address = req.session.address;
        // const pubkey = req.session.pubkey;
        const { tenantAddress, houseAddress } = req.body;
        res.send({ url: 'dataSharing/request?tenant=' + tenantAddress + '&house=' + houseAddress });
    });

    router.get('/request', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const tenant = req.query.tenant;
        const house = req.query.house;
        res.render('leaseSystem/dataSharing/request', { address: address, pubkey: pubkey, tenant: tenant, house: house, contract_address: contract_address });
    });

    router.post('/saveData', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const { nameInput, emailInput, phoneInput, jobInput, salaryInput, depositInput, ownerAddress, ownerPubkey, houseAddress } = req.body;

        let localData;
        try {
            localData = await PersonalData.findOne({ address: address });
            if (!localData) {
                localData = new PersonalData({ address: address, pubkey: pubkey, name: nameInput, email: emailInput, phone: phoneInput, job: jobInput, salary: salaryInput, deposit: depositInput });
                localData.save();
            }
            else {
                localData = await PersonalData.findOneAndUpdate({ address: address },
                    { name: nameInput, email: emailInput, phone: phoneInput, job: jobInput, salary: salaryInput, deposit: depositInput }, { new: true });
            }
            res.render('leaseSystem/dataSharing/upload', {
                address: address, pubkey: pubkey, owner: ownerAddress, ownerPubkey: ownerPubkey
                , house: houseAddress, tenantData: localData, contract_address: contract_address
            });
        } catch (error) {
            console.log(error);
            // res.send({ msg: 'save data error.' });
        }
    })

    router.post('/updatePermission', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { name, email, job, salary, deposit } = req.body;
        const { userPubkey, dataRequester } = req.body;
        let attributes = {
            "name": name,
            "email": email,
            "job": job,
            "salary": salary,
            "deposit": deposit
        }
        let attString = JSON.stringify(attributes);

        // save to chain offline sign
        try {
            // userPubkey, dataRequester, attribute, endTime
            let result = await accInstance.submitTransaction('UpdatePermission', userPubkey, dataRequester, attString, "endTime");
            console.log(result.toString());
            return res.send({ msg: "update success." });

            // const digest = await createTransaction(address.toLowerCase(), 'UpdatePermission', userPubkey, dataRequester, attString, "endTime");
            // return res.send({ 'digest': digest });
        } catch (error) {
            console.log(error);
            return res.send({ msg: "update error." });
        }
    });

    router.post('/revokePermission', isAuthenticated, async (req, res) => {
        const { userPubkey, dataRequester, attribute } = req.body;

        // save to chain
        try {
            // userPubkey, dataRequester, attribute
            let result = await accInstance.submitTransaction('RevokePermission', userPubkey, dataRequester, attribute);
            console.log(result.toString());
            return res.send({ msg: "success." });
        } catch (error) {
            console.log(error);
            return res.send({ msg: "error." });
        }
    });

    router.post('/getData', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const { tenantAddress } = req.body;
        const { name, email, job, salary, deposit } = req.body;

        let tenantData = await PersonalData.findOne({ address: tenantAddress });

        // get chain Access control
        let attributes = {};
        attributes.name = name; attributes.email = email; attributes.job = job; attributes.salary = salary; attributes.deposit = deposit;
        // ConfirmMutiPermission(ctx, dataRequester, userPubkey, attributes)
        // let permitBuffer = await accInstance.evaluateTransaction('ConfirmMutiPermission', pubkey, tenantData.pubkey, attributes);
        let permitBuffer = await accInstance.evaluateTransaction('GetPermission', pubkey, tenantData.pubkey);
        // console.log(permitBuffer);
        let permitJson = JSON.parse(permitBuffer.toString());
        console.log(permitJson);

        let data = {};
        Object.keys(permitJson).forEach(async key => {
            if (permitJson[key].data == "true") {
                data[key] = tenantData[key];
            }
            else {
                data[key] = "permission deny";
            }

        })
        console.log(data);


        return res.send({ msg: "done", "data": data });
    });

    router.post('/test', async (req, res) => {
        console.log(req.body);

        return res.send({ msg: "success." });
    });

    return router;
}