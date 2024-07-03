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

    return pubkey
  }

  async NewLease(ctx, userPubkey, estateAddress, rent, dataHash) {
    let lease = await ctx.stub.getState(userPubkey);
    let leaseJson = JSON.parse(lease.toString());
    if (!lease || lease.length === 0) {
      let leaseData =
      {
        Certificate: {},
        Data: {}
      };
      leaseJson = JSON.parse(leaseData.toString());
    }

    if (!leaseJson.Data[estateAddress]) {
      leaseJson.Data[estateAddress] = {};
    }

    leaseJson.Data[estateAddress] = {
      "owner": ownerAddress,
      "address": estateAddress,
      "rent": rent,
      "state": "online",
      "dataHash": dataHash
    }

    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(leaseJson)));
    return "Add Lease successfully." + userPubkey;
  }

  

  async GetLease(ctx, userPubkey, estateAddress) {
    let lease = await ctx.stub.getState(userPubkey);
    if (!lease || lease.length === 0) {
      throw new Error(`The user key:${userPubkey} does not exist`);
    }
    let leaseJson = JSON.parse(lease.toString());
    const leaseData = leaseJson.Address[estateAddress];

    return JSON.stringify(leaseData);
  }
}

exports.contracts = [LeaseRegister];
