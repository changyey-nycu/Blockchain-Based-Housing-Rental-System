// estate agent chaincode
const mongoose = require('mongoose');

const agencySchema = new mongoose.Schema({
    agentAddress: {
        type: String
    },
    ownerAddress: {
        type: String
    },
    houseAddress: {
        type: String
    },
    hashed: {
        type: String
    },
    type: {
        type: String
    },
    date: {
        type: String,
    }
});


module.exports = agencySchema;

