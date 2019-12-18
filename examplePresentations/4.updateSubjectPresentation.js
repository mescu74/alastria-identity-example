const { transactionFactory, UserIdentity } = require('alastria-identity-lib')
let fs = require('fs')
let keythereum = require('keythereum')
let rawdata = fs.readFileSync('../configuration.json')
let configData = JSON.parse(rawdata)

let presentationHashData = fs.readFileSync(`./PSMHashSubject.json`)
let presentationHash = JSON.parse(presentationHashData)

let Web3 = require('web3')
let myBlockchainServiceIp = configData.nodeURL
const web3 = new Web3(new Web3.providers.HttpProvider(myBlockchainServiceIp))

let updateSubjectPresentation = transactionFactory.presentationRegistry.updateSubjectPresentation(web3, presentationHash.psmhash, configData.updateSubjectPresentationTo)

let keyData = fs.readFileSync('../keystore.json')
let keystoreData = JSON.parse(keyData)

let identityKeystore = keystoreData.identityKeystore

let identityPrivateKey
try {
  identityPrivateKey = keythereum.recover(keystoreData.addressPassword, identityKeystore)
} catch (error) {
  console.log("ERROR: ", error)
}

let subjectIdentity = new UserIdentity(web3, `0x${identityKeystore.address}`, identityPrivateKey)

  if(configData.subject == undefined) {
    console.log('You must create an Alastria ID')
    process.exit()
  }

async function main() {
  let updateSubjP = await subjectIdentity.getKnownTransaction(updateSubjectPresentation)
  console.log('(updateSubjectPresentation)The transaction bytes data is: ', updateSubjP)
  web3.eth.sendSignedTransaction(updateSubjP)
    .then(() => {
      let presentationStatus = transactionFactory.presentationRegistry.getSubjectPresentationStatus(web3, configData.subject, presentationHash.psmhash)

      web3.eth.call(presentationStatus)
        .then(result => {
          let resultStatus = web3.eth.abi.decodeParameters(["bool", "uint8"], result)
          let presentationStatus = {
            exist: resultStatus[0],
            status: resultStatus[1]
          }
          configData.subjectPresentationStatus = presentationStatus;
          fs.writeFileSync('../configuration.json', JSON.stringify(configData))
          console.log('presentationStatus ------>', configData.subjectPresentationStatus)
        })
    })
}

main()