import * as CryptoJS from 'crypto-js';

// Encrypt
var ciphertext = CryptoJS.AES.encrypt('my message', 'secret key 123').toString();
console.log(ciphertext)



