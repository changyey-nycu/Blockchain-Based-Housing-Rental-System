const express = require('express');
const router = express.Router();

const LeaseSystemPage = require('./homepage/homepage.router');
const CertificationPage = require('./certification/identityCert.router');
const AgreementPage = require('./agreement/agreement.router');

// DB config
const db1 = require('../config/keys').GovernmentDB_URI;
const db2 = require('../config/keys').LeaseSystemDB_URI;

const db3 = require('../config/keys').AgreementDB_URI;

const mongoose = require('mongoose');
const db1Connection = mongoose.createConnection(db1);
db1Connection.once('open', () => console.log('\x1b[35m%s\x1b[0m', `${db1Connection.name}'s           DB connected by landAdministration`));

const db2Connection = mongoose.createConnection(db2);
db2Connection.once('open', () => console.log('\x1b[35m%s\x1b[0m', `${db2Connection.name}'s      DB connected by leaseSystem`));

// const db3Connection = mongoose.createConnection(db3);
// db3Connection.once('open', () => console.log('\x1b[35m%s\x1b[0m', `${db3Connection.name}'s           DB connected by Bloockchain Test`));

const db3Connection = mongoose.createConnection(db3);
db3Connection.once('open', () => console.log('\x1b[35m%s\x1b[0m', `${db3Connection.name}'s           DB connected by Rental Agreement DB`));

router.use('/certification', CertificationPage(db1Connection))
router.use('/', LeaseSystemPage(db2Connection));
// router.use('/', (db3Connection));
router.use('/agreement', AgreementPage(db3Connection));


module.exports = router;