const fs = require('fs');
const cbor = require('cbor');

function bigintToArray(v) {
    tmp = BigInt(v).toString(16);
    // not sure why it is not padding and buffer does not like it
    if (tmp.length % 2 === 1) tmp = "0" + tmp;
    return Buffer.from(tmp, "hex");
}

function toCBOR(message) {
    let answer = []


    // "to" field
    answer.push(Buffer.from(message.to));

    // "from" field
    answer.push(Buffer.from(message.from));

    // "nonce" field
    answer.push(message.nonce);

    // "value"
    buf = bigintToArray(message.value);
    answer.push(buf);

    // "gasprice"
    buf = bigintToArray(message.gasprice);
    answer.push(buf);

    // "gaslimit"
    buf = bigintToArray(message.gaslimit);
    answer.push(buf);

    // "method"
    answer.push(message.method);

    if (message.params) {
        // "params"
        answer.push(message.params);
    }


    return cbor.encode(answer);
}

let rawData = fs.readFileSync('template.json');
let jsonData = JSON.parse(rawData);

newJsonData = [];
jsonData.forEach(tc => {
    let cborBuf = toCBOR(tc);

    tc['encoded_tx'] = cborBuf.toString('base64');
    tc['encoded_tx_hex'] = cborBuf.toString('hex');
    newJsonData.push(tc);

});

let rawdata = JSON.stringify(newJsonData, null, 4);

fs.writeFileSync('../manual_testvectors.json', rawdata);