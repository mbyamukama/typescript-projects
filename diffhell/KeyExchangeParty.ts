import { DHKeyGroup } from "./DHKeyGroup"
import * as CryptoJS from 'crypto-js';
import { LinkedList } from 'typescript-collections';

export enum KeyType { Public = 1, Private, Secret, Sender };
// Keystore interface. This gets serialized and saved to a secure key storage facility on the device
export enum AuxiliaryInfo {
    PublicKey = 'PublicKey',
    SenderKey = 'SenderKey',
  }

interface SecurityKeyCredentials {
    keyId: number | null;
    owner: string;
    publicKey: string;
    privateKey: string;
    secret: string;
    senderKey: string;
    senderKeyDate: number; //when the sender key was generated
};

export abstract class E2EEUtilities {
    constructor() {

    }
    //computation time = 2ms
    static randomBigInteger(prime: BigInt): bigint {
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
    static modPow(b: bigint | number, e: bigint | number, n: bigint | number): bigint {
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


    /// Returns a unique ascii key of a given size
    static getUniqueKey(size: number): string {
        var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        var len = chars.length;
        var result = "";
        for (let i = 0; i < size; i++) {
            let index = Math.floor(Math.random() * len);
            result += chars.charAt(index);
        }
        return result;
    }

    //SHA-256 hash
    static hash(message: string): string {
        return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
    }
    //SHA-3 224-bit Key Derivation Function
    static SHA3KDF(secret: string): string {
        let longKey = CryptoJS.SHA3(secret, { outputLength: 224 }).toString(CryptoJS.enc.Base64);
        return longKey.replace(/=/g, '');
    }


    //this implementation to be replaced by secure storage. e.g: env vars
    static saveKey(keyType: KeyType, ownerMemberId: string, keyMaterial: string, keyId: number | null) {
        //var key: string = getKey(keyType, owner);
        let jsonCredentials = localStorage.getItem(ownerMemberId);
        if (jsonCredentials == null) jsonCredentials = "{}";  //first time or after credentials have been cleared. force valid json.
        const userCredentials: SecurityKeyCredentials = JSON.parse(jsonCredentials);
        userCredentials.keyId = keyId; //the Id assigned to the auxiliary message by the messenger api
        switch (keyType) {
            case KeyType.Public:
                userCredentials.publicKey = keyMaterial;
                break;
            case KeyType.Private:
                userCredentials.privateKey = keyMaterial;
                break;
            case KeyType.Secret:
                userCredentials.secret = keyMaterial;
                break;
            case KeyType.Sender:
                userCredentials.senderKey = keyMaterial;
                userCredentials.senderKeyDate = Date.now();
                break;
        }
        localStorage.setItem(ownerMemberId, JSON.stringify(userCredentials));
    }

    static getKey(keyType: KeyType, ownerMemberId: string): string {
        let jsonCredentials = localStorage.getItem(ownerMemberId);
        if (jsonCredentials == null) jsonCredentials = "{}";  //first time or after credentials have beeb cleared
        let userCredentials: SecurityKeyCredentials = JSON.parse(jsonCredentials);
        let key: string, senderKeyDate: number;
        switch (keyType) {
            case KeyType.Public:
                key = userCredentials.publicKey;
                break;
            case KeyType.Private:
                key = userCredentials.privateKey;
                break;
            case KeyType.Secret:
                key = userCredentials.secret;
                break;
            case KeyType.Sender:
                key = userCredentials.senderKey;
                senderKeyDate = userCredentials.senderKeyDate;
                break;
        }
        return key;
    }
    static deleteKeys(owner: string) {
        localStorage.removeItem(owner);
    }

    //generate pairs of current user and all other members of the thread. e.g: current member = m1, others=(m2,m3,m4) output is (m1,m2), (m1,m3), (m1,m4)
    static getPairwiseCombinations(memberIds: LinkedList<string>, refMember: string): LinkedList<LinkedList<string>> {
        var pairwiseCombinations = new LinkedList<LinkedList<string>>();
        memberIds.forEach((memberId) => {
            let temp = new LinkedList<string>();
            if (memberId != refMember) {
                temp.add(refMember);
                temp.add(memberId);
                pairwiseCombinations.add(temp);
            }
        });
        return pairwiseCombinations;
    }
    //generate a unique list of member Ids from thread id
    static getUniqueMemberIds(threadList: string[]): LinkedList<string> {
        var list = new Array<string>();
        var result = new LinkedList<string>();
        threadList.forEach((threadId) => {
            var memberIds = threadId.split("_");
            memberIds.forEach((memberId) => {
                list.push(memberId);
            })
        });
        list = Array.from(new Set(list));
        list.forEach((memberId) => {
            result.add(memberId);
        });
        return result;
    }
    static  aesEncrypt(message: string, key: string): string {
        return CryptoJS.AES.encrypt(message, key).toString(); //toString very important otherwise an object will be returned
    }
    static  aesDecrypt(cipherText: string, key: string): string {
        return CryptoJS.AES.decrypt(cipherText, key).toString(CryptoJS.enc.Utf8);
    }
}

export class KeyExchangeParty {

    memberId: string;
    dhKeyGroup: DHKeyGroup;
    senderKey!: string;
    privateKey!: string;
    publicKey!: string;

    constructor(memberId: string) {
        this.memberId = memberId;
        this.dhKeyGroup = new DHKeyGroup(2);
    }
    public deriveKeyPair() {
        const keyPair = this.dhKeyGroup.deriveKeyPair();
        this.privateKey = keyPair[0];
        this.publicKey = keyPair[1];
    }

    public computeSharedSecret(remotePublicKey: string): string {
        var secret = E2EEUtilities.modPow(BigInt(remotePublicKey), BigInt(this.privateKey), this.dhKeyGroup.prime);
        return E2EEUtilities.SHA3KDF(secret.toString());
    }
    public toString = () : string => {
        return `(id: ${this.memberId})`;
    }
    public generateSenderKey() : string{
        this.senderKey = E2EEUtilities.getUniqueKey(32);
        return this.senderKey
      }
           

}
