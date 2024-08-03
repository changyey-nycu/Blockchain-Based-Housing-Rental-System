'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

function uint8arrayToStringMethod(myUint8Arr) {
  return String.fromCharCode.apply(null, myUint8Arr);
}

class RentalAgreement extends Contract {
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

  async CreateAgreement(ctx, PartyAkey, PartyBkey, rentData, agreementHashed) {
    //only admin can create agreement
    let type = ctx.clientIdentity.getAttributeValue("hf.Type");
    if (type != "admin") {
      throw new Error(`only admin can execute.`);
    }

    let agreement = await ctx.stub.getState(PartyAkey);
    let agreementData = {
      Agreement: {}
    };

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      agreementData = {
        Agreement: {}
      };
    }

    agreementData.Agreement[agreementHashed] = {
      "rentData": rentData,
      "partyA": PartyAkey,
      "partyB": PartyBkey,
      "sign": {},
      "agreementHashed": agreementHashed
    }


    await ctx.stub.putState(PartyAkey, Buffer.from(JSON.stringify(agreementData)));
    return "Create Successfully.";
  }

  async PartyASign(ctx, PartyAkey, PartyBkey, agreementHashed, signature) {
    let agreement = await ctx.stub.getState(PartyAkey);
    let agreementData = {
      Agreement: {}
    };

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }

    agreementData.Agreement[agreementHashed].sign["PartyA"] = signature;

    await ctx.stub.putState(PartyAkey, Buffer.from(JSON.stringify(agreementData)));
    return "Sign for Party A Successfully.";
  }

  async CertificatePartyASign(ctx, PartyAkey, PartyBkey) {
    let agreement = await ctx.stub.getState(PartyAkey);
    let agreementData = {
      Agreement: {}
    };

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }

    let signature = agreementData.Agreement[agreementHashed].sign["PartyA"];

    return "Certificate Successfully.";
  }

  
}

exports.contracts = [RentalAgreement];
