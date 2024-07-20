// gov use, to cert user estate and agent
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
const keccak256 = require('keccak256');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));
const mongoose = require('mongoose');

const require_signature = "LeaseSystem?nonce:778";


module.exports = function (dbconnection1, dbconnection3) {
    const RealEstate = dbconnection1.model('realEstates', require('../../models/landAdministration/realEstate'));
    const Agency = dbconnection1.model('agencys', require('../../models/landAdministration/agency'));

    // for test
    const ChainRealEstate = dbconnection3.model('chainrealEstates', require('../../models/test/realEstate'));
    const ChainAgency = dbconnection3.model('agencies', require('../../models/test/agency'));
    // const Chainlease = dbconnection3.model('leases', require('../../models/test/lease'));

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

    router.get('/', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/certification/certification', { address: address});
    });

    router.post('/estateUpload', async (req, res) => {
        const { name, userAddress, IDNumber, houseAddress, area, date } = req.body;
        // check id pair did
        let hashed = keccak256(IDNumber).toString('hex');
        let contractInstance = new web3.eth.Contract(identityManger.output.abi, contract_address);
        let result = await contractInstance.methods.getId().call({ from: userAddress });
        if (result != hashed || !result) {
            let errors = "The ID error.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // check exist
        let obj = await RealEstate.findOne({ IDNumber: IDNumber, houseAddress: houseAddress });
        if (obj) {
            let errors = "The estate data already exists.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // save to gov DB
        try {
            const realEstateData = new RealEstate({
                name: name,
                IDNumber: IDNumber,
                houseAddress: houseAddress,
                area: area,
                date: date
            })
            await realEstateData.save();
        } catch (error) {
            console.log(error);
            return res.send({ msg: "save data error." });
        }

        // save to blockchain
        // check exist
        let obj2 = await ChainRealEstate.findOne({ ownerAddress: userAddress, houseAddress: houseAddress });
        if (obj2) {
            let errors = "The Real Estate data already exists on chain.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // save to chain
        try {
            const ChainRealEstateData = new ChainRealEstate({
                ownerAddress: userAddress,
                houseAddress: houseAddress,
                area: area,
                date: date
            })
            await ChainRealEstateData.save();
        } catch (error) {
            console.log(error);
            return res.send({ msg: "save data error." });
        }

        return res.send({ msg: "success." })
    });

    router.post('/agentUpload', async (req, res) => {
        const { name, userAddress, IDNumber, date } = req.body;

        // check id pair did
        let hashed = keccak256(IDNumber).toString('hex');
        let contractInstance = new web3.eth.Contract(identityManger.output.abi, contract_address);
        let result = await contractInstance.methods.getId().call({ from: userAddress });
        if (result != hashed || !result) {
            let errors = "The ID error.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // check exist
        let obj = await Agency.findOne({ name: name, IDNumber: IDNumber, date: date });
        if (obj) {
            let errors = "The agent data already exists.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // save to gov DB
        try {
            const AgencyData = new Agency({
                name: name,
                IDNumber: IDNumber,
                date: date
            })
            await AgencyData.save();
        } catch (error) {
            console.log(error);
            return res.send({ msg: "save data error." });
        }

        // save to blockchain
        // check exist
        let obj2 = await ChainAgency.findOne({ agentAddress: userAddress });
        if (obj2) {
            let errors = "The agent data already exists on chain.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // save to chain
        try {
            const ChainAgencyData = new ChainAgency({
                agentAddress: userAddress
            })
            await ChainAgencyData.save();
        } catch (error) {
            console.log(error);
            return res.send({ msg: "save data error." });
        }

        return res.send({ msg: "success." })
    });

    return router;
}