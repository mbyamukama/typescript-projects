import * as CryptoJS from 'crypto-js';


let secret="103168664174226415658327234322386242293034389088224908528722150907268104350019065057427329960769053475864302308819152090756139539190117201149924150172146977879711821764869565827996698504378911256965106214640089328110999185005818344840266329530864437555694027631731405797959512984059031946792938919478432604474";
var hash = CryptoJS.MD5("Message");

export function SHA256KDF(secret : string) : string
{
    let longKey= CryptoJS.SHA256(secret)
    console.log(longKey);
   /* let fits = Math.floor(longKey.length/size);
    console.log("fits="+fits);
    var key="";
    for(var i=0; i<longKey.length; i+=fits)
    {
        key+= longKey.charAt(i);
        if(key.length ==size ) break;
    }*/
    return "";
}

