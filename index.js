const args = process.argv.slice(2);
const keyName = (args[0] === undefined) ? 'wallet' : args[0];

let fs = require('fs');

function createKeyFile(filename, key) {
  fs.writeFile(`${keyName}_${filename}`, key, (err)=> {
    if(err) console.log('Create key faild: ', err)
  });
};

var logger = fs.createWriteStream(`${keyName}.pub`, {
    flag: 'a',
  }
);

// create private key
const secureRandom = require('secure-random');

const max = Buffer.from("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 'hex');
let isInvalid = true;
let privateKey = null;

while (isInvalid) {
  privateKey = secureRandom.randomBuffer(32);
  if (Buffer.compare(max, privateKey) === 1) {
    isInvalid = true;
  }
  isInvalid = false;
}

// create public key
var EC = require('elliptic').ec;
var ecdsa = new EC('secp256k1');

const keys = ecdsa.keyFromPrivate(privateKey);
const publicKey = keys.getPublic('hex');

const sha256 = require('js-sha256');
const ripemd160 = require('ripemd160');
let hash = sha256(Buffer.from(publicKey, 'hex'));
let publicKeyHash = new ripemd160().update(Buffer.from(hash, 'hex')).digest();

// create public address
const bs58 = require('bs58');

function createPublicAddress(publicKey) {
  // network: mainnet -> 00: p2pkh, 05: p2sh
  // network: testnet -> 6f: p2pkh, c4: p2sh
  const addPrefix = Buffer.from('6f' + publicKey, 'hex');
  const hashBuffer = sha256(addPrefix);
  const hexHashBuffer = sha256(Buffer.from(hashBuffer, 'hex'));
  const checksum = hexHashBuffer.substring(0, 8);
  const rowAddress = addPrefix.toString('hex') + checksum;

  const address = bs58.encode(Buffer.from(rowAddress, 'hex'));
  return address;
}

// create wallet import formate
function createPrivateKeyWIF(privateKey) {
  const addPrefix = Buffer.from("80" + privateKey, 'hex');
  const hashBuffer = sha256(addPrefix);
  const hexHashBuffer = sha256(Buffer.from(hashBuffer, 'hex'));
  const checksum = hexHashBuffer.substring(0, 8);
  const rowAddress = addPrefix.toString('hex') + checksum;

  const privateKeyWIF = bs58.encode(Buffer.from(rowAddress, 'hex'));
  return privateKeyWIF;
}

const hexPrivateKey = privateKey.toString('hex');
const hexPublicKey = publicKeyHash.toString('hex');
const publicAddress = createPublicAddress(hexPublicKey);
const privateWIF = createPrivateKeyWIF(hexPrivateKey);

// validate public address
var validate = require('bitcoin-address-validation');
const result = validate(publicAddress)

if(result) {
  createKeyFile('privateKey', hexPrivateKey);
  logger.write('validate result: ' + JSON.stringify(result) + '\n');
  logger.write('hexPublicKey: ' + hexPublicKey + '\n');
  logger.write('publicAddress: ' + publicAddress + '\n');
  logger.write('privateWIF: ' + privateWIF + '\n');
} else {
  console.log('Gernerated an invalid address!')
}
