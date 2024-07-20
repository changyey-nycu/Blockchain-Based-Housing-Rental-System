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
    date: {
        type: String
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
    describe: {
        type: String
    }
});


module.exports = Schema;

