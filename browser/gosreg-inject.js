// CryptoKiddie — injectable reference implementation `cadesplugin` emulation for pages loaded
// NATIVELY (e.g. https://service.nalog.ru/gosreg/), where we cannot serve the
// page through the bridge. Signing is delegated cross-origin to the local
// bridge's /__bridge/sign (token-backed, no reference implementation). Inject via:
//   osascript -e 'tell application "Safari" to do JavaScript (read POSIX file "…/gosreg-inject.js") in front document'
(function(){
if(window.__ckCadesShim)return;window.__ckCadesShim=true;
var B='http://127.0.0.1:18888/__bridge';
function P(v){return Promise.resolve(v);}
var CI=null;
function def(){return {thumbprint:'0000000000000000000000000000000000000000',certB64:'',subject:'CN=Rutoken',issuer:'CN=CA',serialNumber:'00',notBefore:1577836800,notAfter:4102444800,subjectCN:'Rutoken'};}
function certInfo(){if(!CI){CI=fetch(B+'/cert-info',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){return (j&&!j.error)?j:def();}).catch(function(){return def();});}return CI;}
function mkCert(info){return {
Thumbprint:info.thumbprint,SubjectName:info.subject,IssuerName:info.issuer,
SerialNumber:info.serialNumber,Version:3,
ValidFromDate:new Date(info.notBefore*1000),ValidToDate:new Date(info.notAfter*1000),
HasPrivateKey:function(){return P(true);},IsValid:function(){return P({Result:true});},
Export:function(){return P(info.certB64);},
PublicKey:function(){return {Algorithm:{FriendlyName:'GOST R 34.10-2012 256 bits',Value:'1.2.643.7.1.1.1.1'}};},
ExtendedKeyUsage:function(){return P({EKUs:{Count:0,Item:function(){return P(null);}}});}
};}
function mkColl(list){return {Count:list.length,Item:function(i){return P(list[i-1]);},Find:function(){return P(mkColl(list));}};}
function mkStore(list){return {Open:function(){return P(undefined);},Close:function(){return P(undefined);},Certificates:mkColl(list)};}
function mkAbout(){var pv={MajorVersion:2,MinorVersion:0,BuildVersion:14590,toString:function(){return '2.0.14590';}};
return {PluginVersion:pv,MajorVersion:2,MinorVersion:0,BuildVersion:14590,Version:'2.0.14590',
CSPName:function(){return P('Reference GOST R 34.10-2012 KC1 CSP');},
CSPVersion:function(){return P({MajorVersion:5,MinorVersion:0,BuildVersion:13000,toString:function(){return '5.0.13000';}});}};}
function mkAttr(){return {propset_Name:function(){return P(undefined);},propset_Value:function(){return P(undefined);},Name:0,Value:''};}
function mkSigner(){var attrs={Add:function(){return P(undefined);}};
return {propset_Certificate:function(){return P(undefined);},propset_Options:function(){return P(undefined);},
propset_TSAAddress:function(){return P(undefined);},AuthenticatedAttributes2:attrs};}
function mkHashed(){var v='';return {propset_Algorithm:function(){return P(undefined);},
propset_DataEncoding:function(){return P(undefined);},SetHashValue:function(h){v=h;return P(undefined);},
Hash:function(){return P(undefined);},Value:v};}
function postSign(content,enc){
// No explicit Content-Type → text/plain → CORS-simple request (no preflight).
return fetch(B+'/sign',{method:'POST',cache:'no-store',body:JSON.stringify({content:String(content==null?'':content),encoding:enc})})
.then(function(r){return r.json();}).then(function(j){if(j&&j.signature){return j.signature;}throw new Error('bridge sign failed: '+((j&&j.error)||'unknown'));});}
function mkSigned(){var _c='',_e='base64';
return {propset_ContentEncoding:function(v){_e=(v===0||v==='0')?'ucs2le':'base64';return P(undefined);},
propset_Content:function(v){_c=(v==null?'':String(v));return P(undefined);},propset_Certificate:function(){return P(undefined);},
SignCades:function(){window.__ckLastSign={method:'SignCades',enc:_e,len:_c.length};return postSign(_c,_e);},
SignHash:function(){window.__ckLastSign={method:'SignHash',enc:_e,len:_c.length};return postSign(_c,_e);},
Sign:function(){window.__ckLastSign={method:'Sign',enc:_e,len:_c.length};return postSign(_c,_e);}};}
function makeAsync(progId){progId=String(progId||'');
if(progId.indexOf('Store')>=0){return certInfo().then(function(info){return mkStore([mkCert(info)]);});}
if(progId.indexOf('About')>=0){return P(mkAbout());}
if(progId.indexOf('CPAttribute')>=0||progId.indexOf('CPAttr')>=0){return P(mkAttr());}
if(progId.indexOf('SignedData')>=0||progId.indexOf('SignedXML')>=0){return P(mkSigned());}
if(progId.indexOf('Signer')>=0){return P(mkSigner());}
if(progId.indexOf('HashedData')>=0){return P(mkHashed());}
return P({});}
var consts={
CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256:101,CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512:111,
CADESCOM_HASH_ALGORITHM_CP_GOST_3411:100,CADESCOM_CADES_BES:1,CADESCOM_CADES_DEFAULT:0,
CADESCOM_BASE64_TO_BINARY:1,CADESCOM_STRING_TO_UCS2LE:0,CADESCOM_ENCODE_BASE64:0,CADESCOM_ENCODE_BINARY:1,
CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME:0,CADESCOM_CURRENT_USER_STORE:2,CADESCOM_LOCAL_MACHINE_STORE:1,
CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED:0,
CAPICOM_CURRENT_USER_STORE:2,CAPICOM_LOCAL_MACHINE_STORE:1,CAPICOM_MY_STORE:'My',
CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED:2,CAPICOM_STORE_OPEN_READ_ONLY:0,
CAPICOM_CERTIFICATE_FIND_SHA1_HASH:0,CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME:1,
CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY:2,CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN:0,
XmlDsigGost3410Url2012256:'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256',
XmlDsigGost3411Url2012256:'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256',
LOG_LEVEL_DEBUG:4,LOG_LEVEL_INFO:2,LOG_LEVEL_ERROR:1};
var cp={set_log_level:function(){},set:function(){},getLastError:function(){return '';},
CreateObjectAsync:function(p){return makeAsync(p);},CreateObject:function(){return {};},
// reference implementation readiness: many pages do `cadesplugin.then(cb)` — resolve immediately.
then:function(onF){try{if(onF)onF();}catch(e){} return P();}};
for(var k in consts){cp[k]=consts[k];}
try{window.cadesplugin=cp;}catch(e){}
try{window.cadesplugin_load_error=false;}catch(e){}
console.log('[CryptoKiddie] cadesplugin emulation injected (gosreg, absolute bridge oracle)');
})();
