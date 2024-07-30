const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    ownerAddress: {
        require: true,
        type: String,
    },
    houseAddress: {
        type: String
    },
    area: {
        type: Number
    },
    city: {
        type: String
    },
    type: {
        type: String
    },
    hashed: {
        type: String
    },
    title: {
        type: String
    },
    state: {
        type: String
    },
    agent: {
        type: String,
        default: "0x"
    },
    rent: {
        type: Number
    },
    describe: {
        type: String
    }
});


module.exports = Schema;

