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
const { Web3 } = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));

const { ethers } = require('ethers');
const { decrypt, encrypt } = require("eth-sig-util");

// HLF
const fabric_common = require("fabric-common");
const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const { buildCAClient, enrollAdmin, registerAndEnrollUser, getAdminIdentity, buildCertUser } = require('../../util/CAUtil');
const { buildCCPOrg4, buildWallet } = require('../../util/AppUtil');

// hash function
var cryptoSuite = fabric_common.Utils.newCryptoSuite();
var hashFunction = cryptoSuite.hash.bind(cryptoSuite);

var caClient;
var agreementChannel, rentalAgreementInstance;

var wallet;
var gateway;
var adminUser;

var partyASign = {};
var partyBSign = {};

const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection) {
    const AgreementData = dbconnection.model('agreements', require('../../models/agreement/agreement'));

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
        await delay(4000);

        // build an in memory object with the network configuration (also known as a connection profile)
        const ccp = buildCCPOrg4();

        // build an instance of the fabric ca services client based on
        // the information in the network configuration
        caClient = buildCAClient(FabricCAServices, ccp, 'ca.org4.example.com');

        const walletPath = path.join(__dirname, '../../wallet/agreement');
        wallet = await buildWallet(Wallets, walletPath);

        mspOrg4 = 'Org4MSP';
        await enrollAdmin(caClient, wallet, mspOrg4);//remember to change ca url http to https

        //get ca admin to register and enroll user
        adminUser = await getAdminIdentity(caClient, wallet)

        // in a real application this would be done only when a new user was required to be added
        // and would be part of an administrative flow
        await registerAndEnrollUser(caClient, wallet, mspOrg4, 'agreement' /*, 'org2.department1'*/);


        // Create a new gateway instance for interacting with the fabric network.
        // In a real application this would be done as the backend server session is setup for
        // a user that has been verified.
        gateway = new Gateway();

        //console.log(JSON.stringify(gateway));
        await gateway.connect(ccp, {
            wallet,
            identity: 'agreement',
            discovery: { enabled: true, asLocalhost: true }
        });

        agreementChannel = await gateway.getNetwork('agreement-channel');
        rentalAgreementInstance = await registerChannel.getContract('RentalAgreement');
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
            case 'PartyASign':
                endorsementStore = partyASign;
                break;
            case 'PartyASign':
                endorsementStore = partyBSign;
                break;
        }

        var paras = [];
        for (var i = 2; i < arguments.length; i++) {
            paras.push(arguments[i])
        }

        // Need to add other contract
        var endorsement = agreementChannel.channel.newEndorsement('RentalAgreement');
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
            case 'PartyASign':
                endorsementStore = partyASign;
                break;
            case 'PartyBSign':
                endorsementStore = partyBSign;
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
        let proposalResponses = await endorsement.send({ targets: agreementChannel.channel.getEndorsers() });
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
            let commitBytes = commit.build(userContext);
            let commitDigest = hashFunction(commitBytes);
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
            case 'PartyASign':
                endorsementStore = partyASign;
                break;
            case 'PartyBSign':
                endorsementStore = partyBSign;
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
        let commit = endorsementStore[arguments[0]];
        commit.sign(arguments[2]);
        let commitSendRequest = {};
        commitSendRequest.requestTimeout = 300000;
        commitSendRequest.targets = agreementChannel.channel.getCommitters();
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
            signature_array[i] = parseInt(signature[i]);
        }
        let signature_buffer = Buffer.from(signature_array);
        return signature_buffer;
    }

    router.post("/proposalAndCreateCommit", isAuthenticated, async (req, res) => {
        try {
            let { signature, func } = req.body;

            let signature_buffer = convertSignature(signature);
            let response = await proposalAndCreateCommit(req.session.address, func, signature_buffer);
            // console.log(response);
            return res.send(response);

        } catch (error) {
            console.log(error);
            return res.send(error);
        }
    });

    router.post("/commitSend", isAuthenticated, async (req, res) => {
        try {
            let { signature, func, estateAddress } = req.body;
            let signature_buffer = convertSignature(signature);
            let response = await commitSend(req.session.address, func, signature_buffer);
            // console.log(response);
            return res.send(response);
        } catch (error) {
            console.log(error);
            return res.send(error);
        }
    })

    return router;
}