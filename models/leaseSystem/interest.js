const mongoose = require('mongoose');

const interestSchema = new mongoose.Schema({
    address: {
        require: true,
        type: String
    },
    ownerAddress: {
        type: String,
    },
    houseAddress: {
        type: String
    }
});

module.exports = interestSchema;