const fs = require('fs');
const cbor = require('cbor');
const blake2 = require('blake2');
const base32Encode = require('base32-encode');
const leb128 = require('@webassemblyjs/leb128');

function bigintToArray(v) {
    let tmp;

    // Adding byte sign
    let signByte = "00";
    if (BigInt(v) < 0) {
        signByte = "01";
    }

    if (v === "") {
        // to test with null bigint
        return Buffer.from(signByte, "hex");
    } else {
        tmp = BigInt(v).toString(16);
        // not sure why it is not padding and buffer does not like it
        if (tmp.length % 2 === 1) tmp = "0" + tmp;
    }

    return Buffer.concat([Buffer.from(signByte, "hex"), Buffer.from(tmp, "hex")]);
}

function toCBOR(tc) {
    let answer = [];

    // "version" field
    answer.push(tc.message.version);

    // "to" field
    answer.push(Buffer.from(tc.message.to, 'hex'));

    // "from" field
    answer.push(Buffer.from(tc.message.from, 'hex'));

    // "nonce" field
    answer.push(tc.message.nonce);

    // "value"
    let buf = bigintToArray(tc.message.value);
    answer.push(buf);

    // "gaslimit"
    answer.push( parseInt(tc.message.gaslimit, 10));

    // "gaspremium"
    buf = bigintToArray(tc.message.gaspremium);
    answer.push(buf);

    // "gasfeecap"
    buf = bigintToArray(tc.message.gasfeecap);
    answer.push(buf);

    // "method"
    answer.push(tc.message.method);

    if (tc.message.params) {
        // "params"
        answer.push(tc.message.params);
    } else {
        answer.push(Buffer.alloc(0));
    }

    return cbor.encode(answer);
}

function formatAddress(a, testnet) {
    let formattedAddress = "f";
    if (testnet) {
        formattedAddress = "t";
    }

    let addressBuffer = Buffer.from(a, 'hex');

    if (addressBuffer.length < 1) {
        // empty address
        return "";
    }

    if (addressBuffer[0] === 0x00) {
        formattedAddress += "0";
        let result = leb128.decodeUInt64(addressBuffer, 1).value;

        formattedAddress += result;
    } else {

        switch (addressBuffer[0]) {
            case 0x01:
                formattedAddress += "1";
                break;
            case 0x02:
                formattedAddress += "2";
                break;
            case 0x03:
                formattedAddress += "3";
                break;
        }

        let h = blake2.createHash('blake2b', {digestLength: 4});
        h.update(addressBuffer);
        let cksm = h.digest();
        let b = Buffer.concat([addressBuffer.slice(1), cksm]);
        let result = base32Encode(b, 'RFC3548', {padding: false});

        formattedAddress += result.toLowerCase();

    }

    return formattedAddress;
}

let rawData = fs.readFileSync('template.json');
let jsonData = JSON.parse(rawData);

newJsonData = [];
jsonData.forEach(tc => {
    let cborBuf = toCBOR(tc);

    // Format address
    tc.message["to"] = formatAddress(tc.message.to, tc.testnet);
    tc.message["from"] = formatAddress(tc.message.from, tc.testnet);

    tc['encoded_tx'] = cborBuf.toString('base64');
    tc['encoded_tx_hex'] = cborBuf.toString('hex');
    newJsonData.push(tc);

});

let rawdata = JSON.stringify(newJsonData, null, 4);

fs.writeFileSync('../tests/testvectors/manual.json', rawdata);
