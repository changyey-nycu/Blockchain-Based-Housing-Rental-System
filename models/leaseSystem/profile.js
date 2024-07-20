const mongoose = require('mongoose');

const MappingSchema = new mongoose.Schema({
    address: {
        type: String
    },
    agent: {
        type: Boolean
    }
});

module.exports = MappingSchema;