'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

function uint8arrayToStringMethod(myUint8Arr) {
  return String.fromCharCode.apply(null, myUint8Arr);
}

class LeaseRegister extends Contract {
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

    return pubkey;
  }

  async NewLease(ctx, userPubkey, owner, estateAddress, rent) {
    let lease = await ctx.stub.getState(userPubkey);
    let leaseJson;
    try {
      if (!lease || lease.length === 0) {
        throw `The user key:${userPubkey} does not exist`;
      }
      leaseJson = JSON.parse(lease.toString());
    }
    catch (error) {
      console.log(error);
      leaseJson =
      {
        Data: {}
      };
    }

    if (!leaseJson.Data[estateAddress]) {
      leaseJson.Data[estateAddress] = {};
    }

    leaseJson.Data[estateAddress] = {
      "uploader": userPubkey,
      "estateAddress": estateAddress,
      "owner": owner,
      "rent": rent,
      "state": "online"
    }

    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(leaseJson)));
    return "Add Lease successfully." + userPubkey;
  }

  async DelLease(ctx, userPubkey, estateAddress) {
    let lease = await ctx.stub.getState(userPubkey);
    let leaseJson = JSON.parse(lease.toString());
    if (!lease || lease.length === 0) {
      return "Lease not exist." + estateAddress;
    }

    if (leaseJson.Data && leaseJson.Data[estateAddress]) {
      delete leaseJson.Data[estateAddress];
    }
    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(leaseJson)));
    return "Update Estate successfully." + userPubkey;
  }

  async GetPersonLease(ctx, userPubkey) {
    let lease = await ctx.stub.getState(userPubkey);
    if (!lease || lease.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    let leaseJson = JSON.parse(lease.toString());
    const leaseData = leaseJson.Data;

    return JSON.stringify(leaseData);
  }

  async GetLease(ctx, userPubkey, estateAddress) {
    let lease = await ctx.stub.getState(userPubkey);
    if (!lease || lease.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    let leaseJson = JSON.parse(lease.toString());
    const leaseData = leaseJson.Data[estateAddress];

    return JSON.stringify(leaseData);
  }
  
  async Signed(ctx, userPubkey, estateAddress) {
    let lease = await ctx.stub.getState(userPubkey);
    if (!lease || lease.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    let leaseJson = JSON.parse(lease.toString());
    leaseJson.Data[estateAddress].state = "signed";

    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(leaseJson)));
    return "Update Lease Signed successfully.";
  }

  async IsLeaseExist(ctx, userPubkey, estateAddress) {
    let lease = await ctx.stub.getState(userPubkey);
    if (lease && lease.length > 0) {
      let leaseJson = JSON.parse(lease.toString());
      return leaseJson.Data.hasOwnProperty(estateAddress);
    }
    else {
      return false;
    }
  }

  async GetAllOnlineLease(ctx) {
    const allResults = [];
    // range query with empty string for startKey and endKey does an open-ended query of all assets in the chaincode namespace.
    const iterator = await ctx.stub.getStateByRange('', '');
    let result = await iterator.next();
    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');

      let record;
      try {
        record = JSON.parse(strValue);
      } catch (err) {
        console.log(err);
        record = strValue;
      }
      console.log(record);
      Object.values(record.Data).forEach(value => {
        if (value.state == "online") {
          console.log(value);
          allResults.push(record);
        }
      });

      result = await iterator.next();
    }
    return JSON.stringify(allResults);
  }
}

exports.contracts = [LeaseRegister];
