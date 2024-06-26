const mongoose = require('mongoose');

const agencySchema = new mongoose.Schema({
    Name: {
        require: true,
        type: String,
    },
    IDNumber: {
        require: true,
        type: String,
    },
    date: {
        type: String,
        unique: true
    }
});


module.exports = agencySchema;

