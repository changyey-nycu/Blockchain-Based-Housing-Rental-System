'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

const elliptic = require('elliptic')
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);


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
      //  && await this.VerifySign(ctx, PartyAkey, signature, agreementHashed)
      agreementData.Agreement[agreementHashed].sign["PartyA"] = signature;
    }
    else if (type == "PartyB") {
      //  && await this.VerifySign(ctx, PartyBkey, signature, agreementHashed)
      agreementData.Agreement[agreementHashed].sign["PartyB"] = signature;
    }
    else {
      throw new Error(`The Party type ${type} error`);
    }

    await ctx.stub.putState(PartyAkey, Buffer.from(JSON.stringify(agreementData)));
    return `Sign for ${type} Successfully.`;
  }

  // test for on chain verify(can compare speed with SignAgreement)
  async SignAgreement2(ctx, PartyAkey, PartyBkey, agreementHashed, signature, type) {
    let agreement = await ctx.stub.getState(PartyAkey);
    let agreementData;

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }

    if (type == "PartyA" && await this.VerifySign(ctx, PartyAkey, agreementHashed, signature.split(","))) {
      agreementData.Agreement[agreementHashed].sign["PartyA"] = signature;
    }
    else if (type == "PartyB" && await this.VerifySign(ctx, PartyBkey, agreementHashed, signature.split(","))) {
      agreementData.Agreement[agreementHashed].sign["PartyB"] = signature;
    }
    else {
      throw new Error(`The Party type ${type} error`);
    }

    await ctx.stub.putState(PartyAkey, Buffer.from(JSON.stringify(agreementData)));
    return `Sign for ${type} Successfully.`;
  }

  async VerifySign(ctx, pubkey, plaintext, signature) {
    console.log(signature);
    console.log(plaintext);


    const publickeyObject = ecdsa.keyFromPublic(pubkey, 'hex');
    return publickeyObject.verify(plaintext, Buffer.from(signature));
  }

  async VerifyAgreementSign(ctx, pubkey, agreementHashed) {
    let agreement = await ctx.stub.getState(pubkey);
    let agreementData;

    try {
      agreementData = JSON.parse(agreement.toString());
    } catch (error) {
      throw new Error(`The agreement key:${PartyAkey} does not exist`);
    }
    try {
      let A = false, B = false;
      if (agreementData.Agreement[agreementHashed].sign.PartyA) {
        // var publickeyAObject = ecdsa.keyFromPublic(agreementData.Agreement[agreementHashed].partyA, 'hex');
        // // console.log(agreementData.Agreement[agreementHashed].sign.PartyA.split(","));
        // A = publickeyAObject.verify(agreementHashed, Buffer.from(agreementData.Agreement[agreementHashed].sign.PartyA));
        A = await this.VerifySign(ctx, agreementData.Agreement[agreementHashed].partyA, agreementHashed, agreementData.Agreement[agreementHashed].sign.PartyA.split(","));
      }
      if (agreementData.Agreement[agreementHashed].sign.PartyB) {
        // var publickeyBObject = ecdsa.keyFromPublic(agreementData.Agreement[agreementHashed].partyB, 'hex');
        // B = publickeyBObject.verify(agreementHashed, Buffer.from(agreementData.Agreement[agreementHashed].sign.PartyB));
        B = await this.VerifySign(ctx, agreementData.Agreement[agreementHashed].partyB, agreementHashed, agreementData.Agreement[agreementHashed].sign.PartyB.split(","));
      }
      return A && B;
    } catch (error) {
      console.log(error);
      return false;
    }
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
