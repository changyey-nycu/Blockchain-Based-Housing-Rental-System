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
    

    return router;
}