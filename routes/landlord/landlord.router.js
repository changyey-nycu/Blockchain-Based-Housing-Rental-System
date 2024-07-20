const express = require('express');
const fs = require('fs');
const router = express.Router();

// session
const passport = require('passport');
const LocalStrategy = require('passport-local');

const config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const { Web3 } = require('web3');
const keccak256 = require('keccak256');
const web3 = new Web3(new Web3.providers.HttpProvider(config.web3_provider));


const require_signature = "LeaseSystem?nonce:778";

const mongoose = require('mongoose');

module.exports = function (dbconnection2, dbconnection3) {
    const HouseData = dbconnection2.model('houseDatas', require('../../models/leaseSystem/houseData'));
    const Profile = dbconnection2.model('profiles', require('../../models/leaseSystem/profile'));

    // for test
    const ChainRealEstate = dbconnection3.model('chainrealEstates', require('../../models/test/realEstate'));
    const ChainAgency = dbconnection3.model('agencies', require('../../models/test/agency'));
    const Chainlease = dbconnection3.model('leases', require('../../models/test/lease'));

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
        res.render('leaseSystem/landlord/landlord', { address: address });
    });

    router.get('/upload', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/upload', { address: address });
    });

    router.get('/manageEstate', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await HouseData.find({ ownerAddress: address });
        res.render('leaseSystem/landlord/manageEstate', { address: address, HouseData: obj });
    });

    router.post('/estatePage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: req.body.addr });
        res.render('leaseSystem/landlord/estatePage', { address: address, HouseData: obj });
    });


    router.post('/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        res.send({ url: 'agent?addr=' + addr });
    });

    router.get('/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;

        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: addr });
        let obj2 = await Profile.find({ agent: true });
        res.render('leaseSystem/landlord/landlordAgnet', { address: address, HouseData: obj, agentList: obj2 });
    });

    router.post('/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const { addr } = req.body;
        res.send({ url: 'rent?addr=' + addr });
    });


    router.get('/rent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        const addr = req.query.addr;
        let obj = await HouseData.findOne({ ownerAddress: address, houseAddress: addr });
        res.render('leaseSystem/landlord/rent', { address: address, HouseData: obj });
    });


    router.post('/estateBind', isAuthenticated, async (req, res) => {
        // get chain data, then create a record in system DB
        const { userAddress, houseAddress } = req.body;

        // get chain data
        let obj2 = await ChainRealEstate.findOne({ ownerAddress: userAddress, houseAddress: houseAddress });
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

    router.post('/estateUpdate', isAuthenticated, async (req, res) => {
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

    return router;
}