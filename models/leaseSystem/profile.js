const mongoose = require('mongoose');

const MappingSchema = new mongoose.Schema({
    address: {
        type: String
    },
    agent: {
        type: Boolean
    },
    pubkey: {
        type: String
    }
});

module.exports = MappingSchema;