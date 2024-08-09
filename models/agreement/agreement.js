const mongoose = require('mongoose');

const agreementSchema = new mongoose.Schema({
    ownerAddress: {
        require: true,
        type: String,
    },
    tenantAddress:{
        require: true,
        type: String,
    },
    houseAddress: {
        type: String
    },
    area: {
        type: Number
    },
    time: {
        type: String
    },
    hashed: {
        type: String
    },
    state: {
        type: String
    },
    rent: {
        type: Number
    },
    content: {
        type: String
    }
});


module.exports = agreementSchema;

