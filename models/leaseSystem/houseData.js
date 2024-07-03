const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    owner: {
        require: true,
        type: String,
    },
    date: {
        type: String
    },
    city: {
        type: String
    },
    localtion: {
        type: String
    },
    hashed: {
        type: String
    }
});


module.exports = Schema;

