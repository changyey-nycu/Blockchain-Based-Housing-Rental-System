const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    owner: {
        require: true,
        type: String,
    },
    bind: {
        require: true,
        type: String
    },
    status: {
        type: Boolean,
        default: false
    },
    address: {
        type: String,
        default: '0x'
    },
    hashed: {
        type: String
    }
});


module.exports = Schema;

