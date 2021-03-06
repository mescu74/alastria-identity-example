const {transactionFactory, UserIdentity, config} = require('alastria-identity-lib')
const fs = require('fs')
const Web3 = require('web3')
const keythereum = require('keythereum')

let rawdata = fs.readFileSync('./configuration.json')
let configData = JSON.parse(rawdata)

// Init your blockchain provider
let myBlockchainServiceIp = configData.nodeURL
const web3 = new Web3(new Web3.providers.HttpProvider(myBlockchainServiceIp))

console.log('\n ------ Example of prepare Alastria ID, addKey and createAlastrisID necessary to have an Alastria ID ------ \n')
// Data
const rawPublicKey = configData.rawPublicKey

let adminKeyStore = configData.adminKeyStore

let adminPrivateKey
try{
	adminPrivateKey = keythereum.recover(configData.addressPassword, adminKeyStore)
}catch(error){
	console.log("ERROR: ", error)
}

let adminIdentity = new UserIdentity(web3, `0x${adminKeyStore.address}`, adminPrivateKey)

let identityKeystore = configData.identityKeystore

let subjectPrivateKey
try{
	subjectPrivateKey = keythereum.recover(configData.addressPassword, identityKeystore)
}catch(error){
	console.log("ERROR: ", error)
}

let subjectIdentity = new UserIdentity(web3, `0x${identityKeystore.address}`, subjectPrivateKey)
// End data

console.log('\n ------ Step one---> prepareAlastriaID inside a Promise ------ \n')
let p1 = new Promise (async(resolve, reject) => {
	let preparedId = await transactionFactory.identityManager.prepareAlastriaID(web3, identityKeystore.address)
	resolve(preparedId)
})

console.log('\n ------ Step two---> createAlsatriaID inside a second Promise ------ \n')
let p2 = new Promise(async(resolve, reject) => {
	let txCreateAlastriaID = await transactionFactory.identityManager.createAlastriaIdentity(web3, rawPublicKey)
	resolve(txCreateAlastriaID)
})

console.log('\n ------ Step three---> A promise all where prepareAlastriaID and createAlsatriaID transactions are signed and sent ------ \n')
Promise.all([p1, p2])
.then(async values => {
	let signedCreateTransaction =	await subjectIdentity.getKnownTransaction(values[1])
	let signedPreparedTransaction = await adminIdentity.getKnownTransaction(values[0])
	web3.eth.sendSignedTransaction(signedPreparedTransaction)
	.on('transactionHash', function (hash) {
		console.log("HASH: ", hash)
	})
	.on('receipt', function (receipt) {
		console.log("RECEIPT: ", receipt)
		web3.eth.sendSignedTransaction(signedCreateTransaction)
		.on('transactionHash', function (hash) {
				console.log("HASH: ", hash)
		})
		.on('receipt', function (receipt) {
				console.log("RECEIPT: ", receipt)
				web3.eth.call({
					to: config.alastriaIdentityManager,				       
					data: web3.eth.abi.encodeFunctionCall(config.contractsAbi['AlastriaIdentityManager']['identityKeys'], [identityKeystore.address])
				})
				.then (AlastriaIdentity => {
					console.log(`AlastriaIdentity: 0x${AlastriaIdentity.slice(26)}`)
				})
		})
		.on('error', console.error); // If a out of gas error, the second parameter is the receipt.
	})
	.on('error', console.error); // If a out of gas error, the second parameter is the receipt.
})

