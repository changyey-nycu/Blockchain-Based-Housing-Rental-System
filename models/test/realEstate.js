// estate register chaincode
const mongoose = require('mongoose');

const chainRealEstateSchema = new mongoose.Schema({
    ownerAddress: {
        require: true,
        type: String
    },
    houseAddress: {
        require: true,
        type: String
    },
    area: {
        require: true,
        type: Number
    },
    date: {
        type: String
    }
});


module.exports = chainRealEstateSchema;

