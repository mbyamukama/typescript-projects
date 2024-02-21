import CryptoJS, { SHA3 } from 'crypto-js';
import { LinkedList } from 'typescript-collections';


const prime = BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");

const generator = 2;

   //SHA-256 hash
function hash(message: string): string {
    return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
}
//SHA-3 224-bit Key Derivation Function. Uses Keccak Padding by default
 function SHA3KDF(secret: string): string {
    let longKey = CryptoJS.SHA3(secret, { outputLength: 224 }).toString(CryptoJS.enc.Base64);
    return longKey.replaceAll("=","");
}

function aesEncrypt(message: string, key: string): string {
    return CryptoJS.AES.encrypt(message, key).toString(); //toString very important otherwise an object will be returned
}
function aesDecrypt(cipherText: string, key: string): string {
    return CryptoJS.AES.decrypt(cipherText, key).toString(CryptoJS.enc.Utf8);
}
function randomBigInteger(prime: BigInt): bigint {
    var digits = prime.toString().length, tempLen = 0, result = "";
    var expLen = Math.floor((digits / 2) + Math.random() * (digits - digits / 2)); //choose a number of digits between digits/2 and digits for the result
    while (tempLen <= expLen) {
        result += Math.floor((Math.random() * 1e15)).toString();
        tempLen = result.length;
    }
    result = result.slice(0, -1 * (tempLen - expLen));
    return BigInt(result);
}

//fast algorithm for modular exponentiation 
function modPow(b: bigint | number, e: bigint | number, n: bigint | number): bigint {
    if (typeof b === 'number') b = BigInt(b)
    if (typeof e === 'number') e = BigInt(e)
    if (typeof n === 'number') n = BigInt(n)

    var accum = BigInt(1), apow = b;
    var x = e;
    while (x != BigInt(0)) {
        if (x & BigInt(0x01))
            accum = (accum * apow) % n;
        x >>= BigInt(1);
        apow = (apow * apow) % n;
    };
    return accum;
}
function deriveKeyPair(): string[] {
    var privateKey = randomBigInteger(prime);
    var publicKey = modPow(generator, privateKey, prime); //g^pk % p
    return [privateKey.toString(), publicKey.toString()];
}
function computeSharedSecret(userPrivateKey: string, remotePublicKey: string): BigInt {
    var secret = modPow(BigInt(remotePublicKey), BigInt(userPrivateKey), prime);
    return secret;
}

/*let keypair = deriveKeyPair();
console.log(keypair[0]);
console.log(keypair[1]);*/

    //generate a unique list of member Ids from thread id
    function getUniqueMemberIds(threadList: string[]): LinkedList<string> {
        var list = new Array<string>();
        var result = new LinkedList<string>();
        threadList.forEach((threadId) => {
            list = threadId.split("_");
            list.forEach((thread) => {
                if(!result.contains(thread)) result.add(thread);
            });
        });
        return result;
    }

const priK = "90838346188221479819134274375981428574149633982447085164354597894978565623825766050219199631093207285422788670678296336823328705091705261256021892037814558595712159473807496160237263879196223455215543280204742010101149887941447514984752718840547744956379944030315643252118109664";
const pubK ="139868834008915743156920631770486596026177144482390450222820265869182748394209218752695456106259790209659017434758700362246291248203559331008763548757984425093144994394913507886471011278952991275233169403745806112993352770193124688902944050591530003310789954535887184474603475140611585415071538332862366572520";
const  remotepubK ="97871917053353007169950714015280189960187305983018648271103120930470755344866738928905177078347000279004768401696044596794163714164697205392848215199607188316965330160043502966324139225692829580019054145188752144442351872871253355167163553827045839623858975221043726742957894387898030680555749002047857030372";

const  secret = computeSharedSecret(priK, remotepubK);
var dhsecret = SHA3KDF(secret.toString());

var code = "911446";
console.log(SHA3KDF(code));
console.log("puCm5OQWTq2bUfZyebKAjD89NenzsZPfOl3eJQ");

 

