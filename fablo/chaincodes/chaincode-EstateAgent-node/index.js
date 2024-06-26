'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');
const { Certificate } = require('crypto');

function uint8arrayToStringMethod(myUint8Arr) {
  return String.fromCharCode.apply(null, myUint8Arr);
}

class EstateAgent extends Contract {
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

  async NewAgent(ctx, userPubkey) {
    //only admin can add a new User key
    let type = ctx.clientIdentity.getAttributeValue("hf.Type");
    let agent = await ctx.stub.getState(userPubkey);

    if (type != "admin") {
      throw new Error(`only admin can execute.`);
    }
    if (agent && agent.length > 0) {
      throw new Error(`User already exists`);
    } else {
      let agentData =
      {
        Certificate: {},
        Data: {}
      };

      agentData.Certificate = {
        "address": userPubkey
      }
      await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(agentData)));
      return "Create Successfully."
    }
  }

  async AddEstate(ctx, agentPubkey, estateAddress, ownerAddress, data) {
    //only admin can add a new User data
    let estate = await ctx.stub.getState(agentPubkey);

    let key = GetIdentity();
    if (ownerAddress != key) {
      throw new Error(`only owner can execute.`);
    }

    if (!estate || estate.length === 0) {
      throw new Error(`The agent key:${agentPubkey} does not exist`);
    }

    let estateJson = JSON.parse(estate.toString());

    if (!estateJson.Data[estateAddress]) {
      estateJson.Data[estateAddress] = {};
    }

    estateJson.Data[estateAddress] = {
      "owner": ownerAddress,
      "address": estateAddress,
      "data": data
    }

    await ctx.stub.putState(agentPubkey, Buffer.from(JSON.stringify(estateJson)));
    return "Update Estate successfully." + agentPubkey;
  }

  async GetEstate(ctx, userPubkey, estateAddress) {
    let estate = await ctx.stub.getState(userPubkey);
    if (!estate || estate.length === 0) {
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }
    let estateJson = JSON.parse(estate.toString());
    const estateData = estateJson.Address[estateAddress];

    return JSON.stringify(estateData);
  }

}

exports.contracts = [EstateAgent];
