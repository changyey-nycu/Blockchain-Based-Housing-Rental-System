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

    router.post('/upload', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const { ownerAddress, houseAddress } = req.body;
        res.send({ url: 'dataSharing/upload?owner=' + ownerAddress + '&house=' + houseAddress });
    });

    router.get('/upload', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const owner = req.query.owner;
        const house = req.query.house;
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
        res.render('leaseSystem/dataSharing/upload', {
            address: address, pubkey: pubkey, owner: owner
            , house: house, tenantData: localData, contract_address: contract_address
        });
    });

    router.post('/request', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const { tenantAddress, houseAddress } = req.body;
        res.send({ url: 'dataSharing/request?tenant=' + tenantAddress + '&house=' + houseAddress });
    });

    router.get('/request', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const pubkey = req.session.pubkey;
        const tenant = req.query.tenant;
        const house = req.query.house;
        // let localData;
        // try {
        //     localData = await PersonalData.findOne({ address: tenant });
        //     if (!localData) {
        //         localData = new PersonalData({ address: tenant });
        //         localData.save();
        //     }
        // } catch (error) {
        //     console.log(error);
        // }
        res.render('leaseSystem/dataSharing/request', { address: address, pubkey: pubkey, tenant: tenant, house: house, contract_address: contract_address });
    });

    router.post('/saveData', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { nameInput, emailInput, phoneInput, jobInput, salaryInput, depositInput } = req.body;
        let localData;
        try {
            localData = await PersonalData.findOne({ address: address });
            if (!localData) {
                localData = new PersonalData({ address: address, pubkey: pubkey, name: nameInput, email: emailInput, phone: phoneInput, job: jobInput, salary: salaryInput, deposit: depositInput });
                localData.save();
                res.send({ msg: 'save data success.' });
            }
            localData = await PersonalData.findOneAndUpdate({ address: address },
                { name: nameInput, email: emailInput, phone: phoneInput, job: jobInput, salary: salaryInput, deposit: depositInput }, { new: true });
            res.send({ msg: 'save data success.' });

        } catch (error) {
            console.log(error);
            res.send({ msg: 'save data error.' });
        }
    })

    router.post('/updatePermission', isAuthenticated, async (req, res) => {
        const { name, email, job, salary, deposit } = req.body;

        // save to chain
        try {
            let result = await accInstance.submitTransaction('UpdatePermission', userPubkey, houseAddress, area, date);
            console.log(result.toString());
            return res.send({ msg: "success." });
        } catch (error) {
            console.log(error);
            return res.send({ msg: "error." });
        }
    });

    router.post('/getData', isAuthenticated, async (req, res) => {
        const { tenantAddress } = req.body;
        const {name, email, job, salary, deposit} = req.body;
        // get chain Access control
        let { dataRequester, userPubkey } = req.body;
        let permitBuffer = await accInstance.evaluateTransaction('GetPermission', dataRequester, userPubkey);
        let permit = (permitBuffer.toString() === 'true');
        if (permit) {
            try {
                // get data
                return res.send({ msg: "success." });
            } catch (error) {
                console.log(error);
                return res.send({ msg: "permission denied." });
            }
        }
        return res.send({ msg: "permission denied." });
    });

    router.post('/test', async (req, res) => {
        console.log(req.body);

        return res.send({ msg: "success." });
    });

    return router;
}