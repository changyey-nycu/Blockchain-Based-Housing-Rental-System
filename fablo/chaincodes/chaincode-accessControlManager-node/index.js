'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');
//const ethSigUtil = require("eth-sig-util");

function uint8arrayToStringMethod(myUint8Arr) {
  return String.fromCharCode.apply(null, myUint8Arr);
}

class AccessControlManager extends Contract {
  async AddPersonalAccessControl(ctx, userPubkey) {
    //only admin can add a new User key
    let type = ctx.clientIdentity.getAttributeValue("hf.Type");
    let acc = await ctx.stub.getState(userPubkey);

    if (type != "admin") {
      throw new Error(`only admin can execute.`);
    }
    if (acc && acc.length > 0) {
      throw new Error(`User already exists`);
    } else {
      let accessControl =
      {
        Permission: {} // only user can change
      };
      await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(accessControl)));
      return "Create Successfully."
    }
  }
  async GetUserAccControl(ctx, key) {
    //Only the organization that public in acc can read
    let pubkey = await this.GetIdentity(ctx);
    const acc = await ctx.stub.getState(key);

    if (!acc || acc.length === 0) {
      throw new Error(`The user acc key:${key} does not exist`);
    }

    return acc.toString();
  }
  async UserAccControlExist(ctx, key) {
    const acc = await ctx.stub.getState(key);
    return acc && acc.length > 0;
  }
  async GetIdentity(ctx) {
    let org = ctx.clientIdentity.getMSPID();
    let ID = ctx.clientIdentity.getID();
    let IDBytes = ctx.clientIdentity.getIDBytes();

    let secureContext = tls.createSecureContext({
      cert: uint8arrayToStringMethod(IDBytes)
    });
    let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
    let cert = secureSocket.getCertificate();
    //console.log(cert)
    let pubkey = cert.pubkey.toString('hex');

    return pubkey
  }
  async Deletekey(ctx, key) {
    const exists = await this.UserAccControlExist(ctx, key);
    if (!exists) {
      throw new Error(`The key ${key} does not exist`);
    }
    return ctx.stub.deleteState(key);
  }
  async UpdatePermission(ctx, userPubkey, dataRequester, dataValue, dataType, startTime, endTime) {
    let acc = await ctx.stub.getState(userPubkey);

    if (!acc || acc.length === 0) {
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }

    let accJson = JSON.parse(acc.toString());

    if (!accJson.Permission) {
      accJson.Permission = {};
    }

    if (!accJson.Permission[dataRequester]) {
      accJson.Permission[dataRequester] = {};
    }

    accJson.Permission[dataRequester][dataType] = {
      "data": dataValue,
      "startTime": startTime,
      "endTime": endTime
    };

    await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
    return "Update Permission successfully." + pubkey;
  }

  async RevokePermission(ctx, userPubkey, dataRequester, dataValue, dataType) {
    let acc = await ctx.stub.getState(userPubkey);

    if (!acc || acc.length === 0) {
      throw new Error(`The user acc key:${pubkey} does not exist`);
    }

    let accJson = JSON.parse(acc.toString());

    if (accJson.Permission[dataRequester] &&
      accJson.Permission[dataRequester][dataType] &&
      accJson.Permission[dataRequester][dataType].data === dataValue) {
      delete accJson.Permission[dataRequester][dataType];
    }

    await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
    return "Permission revoked successfully.";
  }

  async GetPermission(ctx, dataRequester, userPubkey) {
    let acc = await ctx.stub.getState(userPubkey);
    if (!acc || acc.length === 0) {
      throw new Error(`The user acc key:${pubkey} does not exist`);
    }
    let accJson = JSON.parse(acc.toString());
    const permissions = accJson.Permission[dataRequester];
    if (!permissions) {
      throw new Error(`permission denied!`);
    }
    return JSON.stringify(permissions);
  }
}
exports.contracts = [AccessControlManager];