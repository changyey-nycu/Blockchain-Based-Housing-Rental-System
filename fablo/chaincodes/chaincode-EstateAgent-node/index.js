'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

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

  async NewAgent(ctx, userPubkey, expDate) {
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
        Agreement: {}
      };

      agentData.Certificate = {
        "address": userPubkey,
        "expDate": expDate
      }
      await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(agentData)));
      return "Create Successfully.";
    }
  }

  async AddEstate(ctx, agentPubkey, estateAddress, ownerAddress, type) {
    // only house owner can add a new agreement
    let agent = await ctx.stub.getState(agentPubkey);

    let key = GetIdentity();
    if (ownerAddress != key) {
      throw new Error(`only house owner can execute.`);
    }

    if (!agent || agent.length === 0) {
      throw new Error(`The agent key:${agentPubkey} does not exist`);
    }

    let agentJson = JSON.parse(agent.toString());

    if (!agentJson.Agreement[estateAddress]) {
      agentJson.Agreement[estateAddress] = {};
    }

    agentJson.Agreement[estateAddress] = {
      "ownerAddress": ownerAddress,
      "estateAddress": estateAddress,
      "type": type,
      "state": "propose"
    }

    await ctx.stub.putState(agentPubkey, Buffer.from(JSON.stringify(agentJson)));
    return "Update Estate successfully." + agentPubkey;
  }

  async AcceptEstate(ctx, userPubkey) {
    let agent = await ctx.stub.getState(userPubkey);
    if (!agent || agent.length === 0) {
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }

    let key = GetIdentity();
    if (userPubkey != key) {
      throw new Error(`only the agent can execute.`);
    }

    let agentJson = JSON.parse(agent.toString());
    agentJson.Agreement[estateAddress].state = "accept";

    await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(agentJson)));
    return "accept success";
  }

  async GetAgent(ctx, userPubkey) {
    let agent = await ctx.stub.getState(userPubkey);
    if (!agent || agent.length === 0) {
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }
    let agentJson = JSON.parse(agent.toString());
    const agentData = agentJson.Certificate;

    return JSON.stringify(agentData);
  }

  async GetAgentEstate(ctx, userPubkey) {
    let agent = await ctx.stub.getState(userPubkey);
    if (!agent || agent.length === 0) {
      throw new Error(`The user acc key:${userPubkey} does not exist`);
    }
    let agentJson = JSON.parse(agent.toString());
    const agentData = agentJson.Agreement;

    return JSON.stringify(agentData);
  }

}

exports.contracts = [EstateAgent];
