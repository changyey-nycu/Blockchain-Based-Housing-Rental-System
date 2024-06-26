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
    // const houseData = dbconnection.model('houseData', require('../../models/leaseSystem/houseData'));
    
    var isAuthenticated = function (req, res, next) {
        console.log('isAuthenticated : ' + req.isAuthenticated());
        if (req.isAuthenticated()) {
            next();
        } else {
            req.flash('info', 'Login first.');
            res.redirect('/LeaseSystem/homepage');
        }
    };

    router.get('/', (req, res) => {
        res.render('leaseSystem/homepage', { 'require_signature': require_signature, 'contract_address': contract_address });
    });

    router.get('/homepage', (req, res) => {
        res.render('leaseSystem/homepage', { 'require_signature': require_signature, 'contract_address': contract_address });
    });

    router.get('/login', (req, res) => {
        res.render('leaseSystem/login', { 'require_signature': require_signature, 'contract_address': contract_address });
    });

    router.post('/loginWithMetamask', passport.authenticate('verifySign_LeaseSystem', {
        failureRedirect: '/leaseSystem'
    }), async function (req, res) {
        const address = req.user.address;
        req.session.address = address;
        res.send({ 'url': '/leaseSystem/profile' });
    });

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

    router.get('/leaseHouse', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/leaseHouse', { address: address });
    });

    router.get('/estateManage', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/estateManage', { address: address });
    });

    router.get('/agent', isAuthenticated, async (req, res) => {
        const address = req.session.address;
        res.render('leaseSystem/agent', { address: address });
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

    router.post('/loginWithMetamask', passport.authenticate('verifySign_LeaseSystem', {
        failureRedirect: '/leaseSystem'
    }), async function (req, res) {
        const address = req.user.address;
        req.session.address = address;
        res.send({ 'url': '/leaseSystem/profile' });
    });

    return router;
}