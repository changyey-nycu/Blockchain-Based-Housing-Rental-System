'use strict';

const { Contract } = require('fabric-contract-api');

class EstateRegister extends Contract {
  async NewPersonalEstate(ctx, userPubkey) {
    //only admin can add a new User key
    let type = ctx.clientIdentity.getAttributeValue("hf.Type");
    let estate = await ctx.stub.getState(userPubkey);

    if (type != "admin") {
      throw new Error(`only admin can execute.`);
    }
    if (estate && estate.length > 0) {
      throw new Error(`User already exists`);
    } else {
      let estateList =
      {
        Address: {}
      };
      await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(estateList)));
      return "Create Successfully."
    }
  }

  async UpdatePersonalEstate(ctx, userPubkey, estateAddress, estateArea,date) {
    //only admin can add a new User data
    let type = ctx.clientIdentity.getAttributeValue("hf.Type");
    let estate = await ctx.stub.getState(userPubkey);
    if (type != "admin") {
      throw new Error(`only admin can execute.`);
    }

    if (!estate || estate.length === 0) {
      // estateJson =
      // {
      //   Address: {}
      // };
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }
    // else {
    //   estateJson = JSON.parse(estate.toString());
    // }

    let estateJson = JSON.parse(estate.toString());

    if (!estateJson.Address[estateAddress]) {
      estateJson.Address[estateAddress] = {};
    }

    estateJson.Address[estateAddress] = {
      "address": estateAddress,
      "area": estateArea
    }

    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(estateJson)));
    return "Update Estate successfully." + userPubkey;
  }

  async GetPersonEstate(ctx, userPubkey) {
    let estate = await ctx.stub.getState(userPubkey);
    if (!estate || estate.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    const estateJson = JSON.parse(estate.toString());
    return JSON.stringify(estateJson);
  }

  async GetEstate(ctx, userPubkey, estateAddress) {
    let estate = await ctx.stub.getState(userPubkey);
    if (!estate || estate.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    let estateJson = JSON.parse(estate.toString());
    const estateData = estateJson.Address[estateAddress];

    return JSON.stringify(estateData);
  }

  async CheckExist(ctx, userPubkey) {
    let estate = await ctx.stub.getState(userPubkey);
    if (!estate || estate.length === 0) {
      return false;
    }
    return true;
  }

  async CheckEstate(ctx, userPubkey, estateAddress) {
    let estate = await ctx.stub.getState(userPubkey);
    if (!estate || estate.length === 0) {
      return false;
    }

    let estateJson = JSON.parse(estate.toString());
    if (estateJson.Address[estateAddress].owner != userPubkey) {
      return false;
    }

    return true;
  }
}

exports.contracts = [EstateRegister];
