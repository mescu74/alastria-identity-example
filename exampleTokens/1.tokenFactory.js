const { transactionFactory, tokensFactory } = require('alastria-identity-lib')
const { tests } = require('alastria-identity-JSON-objects/tests')
const Web3 = require('web3')
const fs = require('fs')
const keythereum = require('keythereum')

const rawdata = fs.readFileSync('../configuration.json')
const config = JSON.parse(rawdata)

// Init your blockchain provider
const myBlockchainServiceIp = config.nodeUrl

const keyDataSubject = fs.readFileSync(
  '../keystores/subject1-806bc0d7a47b890383a831634bcb92dd4030b092.json'
)
const keystoreDataSubject = JSON.parse(keyDataSubject)

const subjectKeyStore = keystoreDataSubject

let subjectPrivateKey
try {
  subjectPrivateKey = keythereum.recover(config.addressPassword, subjectKeyStore)
} catch (error) {
  console.log('ERROR: ', error)
  process.exit(1)
}

console.log('---- signJWT ----')

const anyJWT = config.tokenPayload
const signedJWT = tokensFactory.tokens.signJWT(anyJWT, subjectPrivateKey)
console.log('\tThe signed JWT is: ', signedJWT)

console.log('\n---- decodeJWT ----')

const decodedJWT = tokensFactory.tokens.decodeJWT(signedJWT)
console.log('\tThe decoded example jwt is: \n', decodedJWT)


console.log('\n---- verifyJWT ----')

// '04' means uncompressed key (more info at https://github.com/indutny/elliptic/issues/138)
const verifyJWT = tokensFactory.tokens.verifyJWT(
  signedJWT,
  '04' + config.subject1Pubk.substr(2)
)
console.log('\tIs the signedJWT verified?', verifyJWT)

//------------------------------------------------------------------------------

console.log('\n---- createAlastriaToken ----')
// Data
const context = config.context
const didIsssuer = config.didEntity3
const providerURL = config.providerURL
const callbackURL = config.callbackURL
const alastriaNetId = config.networkId
const tokenExpTime = config.tokenExpTime
const tokenActivationDate = config.tokenActivationDate
const jsonTokenId = config.jsonTokenId
// End data
const alastriaToken = tokensFactory.tokens.createAlastriaToken(
  didIsssuer,
  providerURL,
  callbackURL,
  alastriaNetId,
  tokenExpTime,
  tokenActivationDate,
  jsonTokenId
)
console.log('\tThe Alastria Token is: \n', alastriaToken)

// Signing the AlastriaToken
const signedAT = tokensFactory.tokens.signJWT(alastriaToken, subjectPrivateKey)
tests.tokens.validateToken(signedAT);

//------------------------------------------------------------------------------

console.log('\n---- createAlastriaSesion ----')

const alastriaSession = tokensFactory.tokens.createAlastriaSession(
  context,
  didIsssuer,
  config.subject1Pubk,
  signedAT,
  tokenExpTime,
  tokenActivationDate,
  jsonTokenId
)
console.log('\tThe Alastria Session is:\n', alastriaSession)

//------------------------------------------------------------------------------

console.log('\n---- createCredential ----')

// Data
const credentialJti = config.credentialJti
const kid = config.kid
const didSubject1 = config.didSubject1
const credentialSubject = {}
const credentialKey = config.credentialKey
const credentialValue = config.credentialValue
credentialSubject[credentialKey] = credentialValue
credentialSubject.levelOfAssurance = 1
// End data

const credential = tokensFactory.tokens.createCredential(
  kid,
  config.didEntity1,
  didSubject1,
  context,
  credentialSubject,
  tokenExpTime,
  tokenActivationDate,
  credentialJti
)
console.log('\nThe credential is: ', credential)
//credential should be signed by the issuer
const signedCredential= tokensFactory.tokens.signJWT(credential, subjectPrivateKey)
console.log('\tThe signed credential is:', signedCredential)
tests.credentials.validateCredential(signedCredential);

//------------------------------------------------------------------------------

console.log('\n---- PSMHash ----')

const web3 = new Web3(new Web3.providers.HttpProvider(myBlockchainServiceIp))

const psmHashSubject = tokensFactory.tokens.PSMHash(
  web3,
  signedJWT,
  config.didSubject1
)
console.log('\tThe PSMHash calculate for the subjectCredentialHash is:', psmHashSubject)

const psmHashReciever = tokensFactory.tokens.PSMHash(
  web3,
  signedJWT,
  config.didEntity2
)
console.log('\tThe PSMHash calculate for the issuerCredentialHash is:', psmHashReciever)

//------------------------------------------------------------------------------

console.log('\n---- createPresentationRequest ----')

// Data
const presentationRequestJti = config.presentationRequestJti
const procUrl = config.procUrl
const procHash = config.procHash
const presentationRequestData = config.presentationRequestData
// End data

const presentationRequest = tokensFactory.tokens.createPresentationRequest(
  kid,
  config.didEntity1,
  context,
  procUrl,
  procHash,
  presentationRequestData,
  callbackURL,
  tokenExpTime,
  tokenActivationDate,
  presentationRequestJti,
  presentationRequestJti
)
console.log('\nThe presentation request is: ', presentationRequest)
const signedPresentationRequest= tokensFactory.tokens.signJWT(presentationRequest, subjectPrivateKey)
console.log('\tThe signed presentation request is:', signedPresentationRequest)
tests.presentationRequests.validatePresentationRequest(signedPresentationRequest);

//------------------------------------------------------------------------------

console.log('\n---- createPresentation ----')

const presentation = tokensFactory.tokens.createPresentation(
  kid,
  config.didSubject1,
  config.didEntity1,
  context,
  config.verifiableCredential,
  procUrl,
  procHash,
  0,
  1,
  config.presentationJti
)
console.log('\nThe presentation is: ', presentation)
const signedPresentation= tokensFactory.tokens.signJWT(presentation, subjectPrivateKey)
console.log('\tThe signed presentation is:', signedPresentation)
tests.presentations.validatePresentation(signedPresentation);

//------------------------------------------------------------------------------

console.log('\n---- Create AIC ----')

// The subject, from the wallet, should build the tx createAlastriaId and sign it
// look at exampleCreateAlastriaID

const aic = tokensFactory.tokens.createAIC(
  config.signedTxCreateAlastriaID,
  signedAT,
  config.subject1Pubk
)
console.log('\tThe AIC is:', aic)

const signedJWTAIC = tokensFactory.tokens.signJWT(aic, subjectPrivateKey)
console.log('\tThe signed AIC is:', signedJWTAIC)
tests.alastriaIdCreations.validateAlastriaIdCreation(signedJWTAIC);
