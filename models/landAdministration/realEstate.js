const mongoose = require('mongoose');

const realEstateSchema = new mongoose.Schema({
    ownerName: {
        require: true,
        type: String,
    },
    IDNumber: {
        require: true,
        type: String,
    },
    address: {
        type: String,
        unique: true
    }
});


module.exports = realEstateSchema;

