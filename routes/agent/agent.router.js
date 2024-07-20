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


const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection1, dbconnection2) {
    const HouseData = dbconnection1.model('houseDatas', require('../../models/leaseSystem/houseData'));
    const Profile = dbconnection1.model('profiles', require('../../models/leaseSystem/profile'));

    // for test
    const ChainRealEstate = dbconnection2.model('chainrealEstates', require('../../models/test/realEstate'));
    const ChainAgency = dbconnection2.model('agencies', require('../../models/test/agency'));
    const Chainlease = dbconnection2.model('leases', require('../../models/test/lease'));

    var isAuthenticated = function (req, res, next) {
        // console.log('isAuthenticated : ' + req.isAuthenticated());
        if (req.isAuthenticated()) {
            next();
        } else {
            req.flash('info', 'Login first.');
            res.redirect('/LeaseSystem/login');
        }
    };

    router.get('/', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await Profile.findOne({ address: address });
        res.render('leaseSystem/agent/agent', { address: address, user: obj });
    });

    router.post('/getCert', isAuthenticated, async (req, res) => {
        // check agent have a cert for agent on chain, and save to localDB
        const { userAddress } = req.body;
        console.log(userAddress);

        // get chain data
        let obj2 = await ChainAgency.findOne({ agentAddress: userAddress });
        if (!obj2) {
            let errors = "The agent data does not exists on chain.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        // save local
        let obj = await Profile.findOneAndUpdate(
            { address: userAddress },
            { agent: true }
        );
        console.log(obj);
        if (!obj) {
            errors = "The agent data error in system.";
            console.log(errors);
            return res.send({ msg: errors });
        }

        return res.send({ msg: "success" });
    });




    return router;
}