'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

// const elliptic = require('elliptic')
// const EC = elliptic.ec;
// const ecdsaCurve = elliptic.curves['p256'];
// const ecdsa = new EC(ecdsaCurve);


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

  async SignAgreement(ctx, PartyAkey, PartyBkey, agreementHashed, signature, type) {
    let agreement = await ctx.stub.getState(PartyAkey);
    let agreementData;

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }

    if (type == "PartyA") {
      // let verify = await this.VerifySign(ctx, PartyAkey, signature, agreementHashed);
      agreementData.Agreement[agreementHashed].sign["PartyA"] = signature;
    }
    else if (type == "PartyB") {
      // let verify = await this.VerifySign(ctx, PartyBkey, signature, agreementHashed);
      agreementData.Agreement[agreementHashed].sign["PartyB"] = signature;
    }
    else {
      throw new Error(`The Party type ${type} error`);
    }

    await ctx.stub.putState(PartyAkey, Buffer.from(JSON.stringify(agreementData)));
    return `Sign for ${type} Successfully.`;
  }

  async VerifySign(ctx, pubkey, signature, plaintext) {
    let decryptSignature = plaintext;
    // var publickeyObject = ecdsa.keyFromPublic(pubkey, 'hex');
    // console.log(publickeyObject.verify(Buffer.from(plaintext), signature));

    if (decryptSignature == plaintext) {
      return true;
    }
    return false;
  }

  async GetAgreement(ctx, PartyAkey, agreementHashed) {
    let agreement = await ctx.stub.getState(PartyAkey);

    let agreementData;
    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }
    return JSON.stringify(agreementData.Agreement[agreementHashed]);
  }
}

exports.contracts = [RentalAgreement];
