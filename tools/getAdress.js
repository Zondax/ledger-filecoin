const blake2 = require('blake2');
const base32Encode = require('base32-encode');

const pubKeys = [
    "0235e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795",
    "02e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa",
    "03cd4569c4fe16556d74dfd1372a2f3ae7b6c43121c7c2902f9ae935b80a7c254b",
    "8D16D62802CA55326EC52BF76A8543B90E2ABA5BCF6CD195C0D6FC1EF38FA1B300"
]

const ntwrk = Buffer.from("01", "hex");

for (let i in pubKeys) {
    pubkey = Buffer.from(pubKeys[i].toLowerCase(), "hex");
    console.log(pubkey);
    let h = blake2.createHash('blake2b', {digestLength: 20});
    h.update(pubkey);
    let payload = h.digest();

    let addressByte = Buffer.concat([ntwrk, payload])

    console.log("byte format address :", addressByte.toString("hex"));

    h = blake2.createHash('blake2b', {digestLength: 4});
    h.update(addressByte);
    let cksm = h.digest();

    let b = Buffer.concat([addressByte.slice(1), cksm]);
    let addressString = base32Encode(b, 'RFC3548', {padding: false});

    console.log("String format address : "+"t1"+addressString.toLowerCase());
}

