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

module.exports = function (dbconnection) {
    var isAuthenticated = function (req, res, next) {
        console.log('isAuthenticated : ' + req.isAuthenticated());
        if (req.isAuthenticated()) {
            next();
        } else {
            req.flash('info', 'Login first.');
            res.redirect('/LeaseSystem/homepage');
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

    router.get('/', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/landlord');
    });

    router.get('/upload', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/upload');
    });

    router.get('/manageEstate', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/manageEstate');
    });

    router.get('/agent', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/agnet');
    });

    router.get('/rent', async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/landlord/rent');
    });

    router.post('/uploadCheck', async (req, res) => {
        const address = req.session.address;
        console.log(req.body);
    });

    return router;
}