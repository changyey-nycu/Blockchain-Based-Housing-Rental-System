// lease register chaincode
const mongoose = require('mongoose');

const realEstateSchema = new mongoose.Schema({
    address: {
        require: true,
        type: String
    },
    hashed: {
        require: true,
        type: String
    },
    rent:{
        require: true,
        type: Number
    },
    date:{
        require: true,
        type: String
    },
});


module.exports = realEstateSchema;

