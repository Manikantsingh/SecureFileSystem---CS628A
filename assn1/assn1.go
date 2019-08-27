package main

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

func main() {

	println("starting program\n")

	userDetails, err := InitUser("mani", "pass")

	println("Init User: ", userDetails.Username, userDetails.Password)

	fetchedDetails, err := GetUser("mani", "pass")
	if err != nil {
		println("User does not exists")
	} else {
		println("Get User: ", fetchedDetails.Username, fetchedDetails.Password)
	}

	secondUser, _ := InitUser("mani2", "pass")

	secondUserFetchedDetails, err := GetUser(secondUser.Username, secondUser.Password)
	if err != nil {
		println("User does not exists")
	} else {
		println("Get User: ", secondUserFetchedDetails.Username, secondUserFetchedDetails.Password)
	}

	data1 := userlib.RandomBytes(4096 * 3)
	fileError := fetchedDetails.StoreFile("filename1", data1)
	if fileError != nil {
		println("**** Unable to store file ****", fileError.Error())
	}

	data3 := userlib.RandomBytes(4096 * 2)
	AppendFileError := fetchedDetails.AppendFile("filename1", data3)
	if AppendFileError != nil {
		println("Something went wrong while appending to the file.")
	}

	data2, _ := fetchedDetails.LoadFile("filename1", 2)

	if !userlib.Equal(data1[configBlockSize*2:configBlockSize*3], data2) {
		println("data corrupted")
	} else {
		println("data is not corrupted")
	}

	// msgid, _ := userDetails.ShareFile("filename1", "mani2")
	// if msgid == "" {
	// 	println("Did not receive any message")
	// }

	// _ = secondUser.ReceiveFile("filename2", "mani", msgid)

	// data4, _ := secondUser.LoadFile("filename2", 2)
	// if !userlib.Equal(data3[configBlockSize:], data4) {
	// 	println("data corrupted")
	// } else {
	// 	println("data is not corrupted")
	// }

	//_ = userDetails.RevokeFile("filename1")

	// data5, _ := secondUser.LoadFile("filename2", 2)
	// if !userlib.Equal(data3[configBlockSize:], data5) {
	// 	println("data corrupted")
	// } else {
	// 	println("data is not corrupted")
	// }

	// data4, _ := userDetails.LoadFile("filename1", 2)
	// if !userlib.Equal(data3[configBlockSize:], data5) {
	// 	println("data corrupted")
	// } else {
	// 	println("data is not corrupted")
	// }

	return

}

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username   string
	Password   string
	RSAPrivKey userlib.PrivateKey
	//BlockCFBKey    []byte
	//FileInfoCFBKey []byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//File structure needs to be store on datastore
type File struct {
	RootIndexUUID uuid.UUID
	BlockCFBKey   []byte
	StackPointer  int
}

type Root struct {
	DP        []byte
	SIP2Block [800][]byte
}

type Block struct {
	Data []byte
	Hmac []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	RootUUIDKey  uuid.UUID
	BlockCFBKey  []byte
	StackPointer int
}

type message struct {
	EncryptedMessage []byte
	Sign             []byte
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	println("Length of the bytes given : ", len(data), " Blocks in file: ", len(data)/configBlockSize)

	//Remember to remove 1!=1
	if (len(data) % configBlockSize) != 0 {
		err = errors.New("File is not a multiple fo file size\n")
	} else {

		//************** Fresh Code *******************

		//Generating file information block index.
		fileIndex := []byte(userdata.Username + filename)
		fileIndexHmac := userlib.NewHMAC(fileIndex)
		fileIndexHmacString := string(fileIndexHmac.Sum(nil))

		rootKeyUUID := bytesToUUID(userlib.RandomBytes(16))

		//*********************************************
		fileInfoBlock := &File{}
		root := &Root{}

		fileInfoBlock.RootIndexUUID = rootKeyUUID

		blocksInFile := len(data) / configBlockSize

		//Setting the actual data in the block with its calculated hmac
		//************ Starting block encryption ************
		block := &Block{}
		block.Data = data[:configBlockSize]
		block.Hmac = userlib.NewHMAC(block.Data).Sum(nil)

		//println("Block Data: ", hex.EncodeToString(block.Data))

		MarshaledBlockData, _ := json.Marshal(block)
		//println("Marshal of block : ", 0, " ", string(MarshaledBlockData))

		//println("Length of Marshaled data: ", string(MarshaledBlockData))
		println("Hmac: ", hex.EncodeToString(block.Hmac))
		//Generate Block CFB encryption and decryption key.
		BlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)

		//Encrypt file with above generated Block CFB
		blockCipherText := make([]byte, userlib.BlockSize+len(MarshaledBlockData))
		iv := blockCipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))
		println("IV : ", hex.EncodeToString(iv), " for block ", " 0  block CFB KEY: ", hex.EncodeToString(BlockCFBKey))

		blockCipher := userlib.CFBEncrypter(BlockCFBKey, iv)
		blockCipher.XORKeyStream(blockCipherText[userlib.BlockSize:], MarshaledBlockData)
		// ********* Block Encryption done ************

		//println("marshaled block:", hex.EncodeToString(blockCipherText[userlib.BlockSize:]))

		currentBlockIndex := 0
		//currentBytePosition := configBlockSize
		root.SIP2Block[currentBlockIndex] = blockCipherText
		currentBlockIndex += 1

		// for i := 1; i < blocksInFile; i++ {
		// 	println("Entred In the loop ceate blocks and store")
		// 	currentBlock := &Block{}
		// 	currentBlock.Data = data[currentBytePosition : currentBytePosition+configBlockSize]
		// 	println("data size: ", len(currentBlock.Data))

		// 	currentBlock.Hmac = userlib.NewHMAC(currentBlock.Data).Sum(nil)

		// 	MarshaledBlock, _ := json.Marshal(currentBlock)

		// 	currentBlockCipher := make([]byte, userlib.BlockSize+len(MarshaledBlock))
		// 	currentBlockIV := blockCipherText[:userlib.BlockSize]
		// 	copy(currentBlockIV, userlib.RandomBytes(userlib.BlockSize))

		// 	blockCipherIntermediate := userlib.CFBEncrypter(BlockCFBKey, currentBlockIV)
		// 	blockCipherIntermediate.XORKeyStream(currentBlockCipher[userlib.BlockSize:], MarshaledBlock)

		// 	root.SIP2Block[currentBlockIndex] = currentBlockCipher

		// 	currentBlockIndex += 1
		// 	currentBytePosition += configBlockSize
		// }

		//println("Store blocks: 0: ", hex.EncodeToString(root.SIP2Block[0]))
		//println("Store blocks: 1: ", hex.EncodeToString(root.SIP2Block[1]))

		MarshaledRoot, _ := json.Marshal(root)
		println("length Root Marshaled ", len(MarshaledRoot))

		rootHMAC := userlib.NewHMAC(MarshaledRoot)
		rootHMacByte := rootHMAC.Sum(nil)
		println("******* Hmac Length : ", hex.EncodeToString(rootHMacByte))

		rootWithHmac := make([]byte, len(rootHMacByte)+len(MarshaledRoot))
		copy(rootWithHmac[:len(rootHMacByte)], rootHMacByte)
		copy(rootWithHmac[len(rootHMacByte):], MarshaledRoot)

		//println("length of the root before storing blockcipher: ", len(rootWithHmac))

		userlib.DatastoreSet(rootKeyUUID.String(), rootWithHmac)
		println("File Stored at : ", rootKeyUUID.String())

		//Generating File CFB
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		fileInfoBlock.BlockCFBKey = BlockCFBKey
		fileInfoBlock.StackPointer = 0 //len(data)/configBlockSize

		MarhsaledFile, _ := json.Marshal(fileInfoBlock)

		fileCipherText := make([]byte, userlib.BlockSize+len(MarhsaledFile))
		fileiv := fileCipherText[:userlib.BlockSize]
		copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

		println("// **************** file iv ************** ", hex.EncodeToString(fileiv))

		//Encrypting file info
		fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
		fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], MarhsaledFile)

		userlib.DatastoreSet(fileIndexHmacString, fileCipherText)
		if blocksInFile > 1 {
			println("More than 1 file ")
			userdata.AppendFile(filename, data[configBlockSize:])
		}
	}
	return err
}

// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	if len(data)%configBlockSize != 0 {
		err = errors.New("Given data is not a multiple of block size")
	}

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	println("// ************* File info stored at : ", hex.EncodeToString(fileIndexHmac))
	fileInfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		println("\nFile not found \n")
		err = errors.New("File not found")
	} else {

		println("//\n ************* Decrypting FileInfo Block  ****************\n")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		println("//\n************* Unmarshaling file info block ******************\n")
		FileInfo := &File{}
		json.Unmarshal(fileInfoBlockPlainText[userlib.BlockSize:], &FileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		BlockIndexKey := FileInfo.RootIndexUUID.String()
		BlockCFBKey := FileInfo.BlockCFBKey
		StackPointer := FileInfo.StackPointer
		println("Root is store at : ", BlockIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		println("//\n*************** Calling Encrypt block and store function *********** \n")
		StackPointer, _ = EncryptBlockAndStore(BlockIndexKey, BlockCFBKey, StackPointer, data, fileIndexHmac)
		println("// **************** Blocks currently present on file ==========> ", StackPointer+1, " \n")

		println("//\n************ update file info block agan with latest stack pointer ************\n")
		FileInfo.StackPointer = StackPointer

		println("// *********** Marshal file info again to store ************")
		marshaledFileInfoAfterUpdate, _ := json.Marshal(FileInfo)

		println("//*********** Encrypt fileInfo again ****************")
		FileInfoCipher := make([]byte, userlib.BlockSize+len(marshaledFileInfoAfterUpdate))
		copy(FileInfoCipher[:userlib.BlockSize], fileIV)
		fileCipherAgain := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherAgain.XORKeyStream(FileInfoCipher[userlib.BlockSize:], marshaledFileInfoAfterUpdate)

		println("// ********** Store encrypted file info back again in datatore ***********", hex.EncodeToString(fileIndexHmac))
		userlib.DatastoreSet(fileIndexString, FileInfoCipher)
		println(" $$$$$$$$$$$$$  encrypted file info  length, ", len(FileInfoCipher))

		println("\nFileSize after appending the file:", len(FileInfoCipher), "\n")

	}

	return err
}

func EncryptBlockAndStore(BlockIndexKey string, BlockCFBKey []byte, StackPointer int, data []byte, fileIndexHmac []byte) (StackTop int, err error) {

	println("// ************ Fetching Root First ***************")
	MarshaledRootWithHmac, ok := userlib.DatastoreGet(BlockIndexKey)
	if !ok {
		err = errors.New("File not found ")
		return 0, err
	}

	println("// \n*********** Verifying HMAC *****************\n")
	RootPreviousHmac := MarshaledRootWithHmac[:len(fileIndexHmac)]
	RootData := MarshaledRootWithHmac[len(fileIndexHmac):]
	CurrentRootHmac := userlib.NewHMAC(RootData).Sum(nil)

	if !userlib.Equal(RootPreviousHmac, CurrentRootHmac) {
		println("\nThere is some issue with  MAC : PreviousHMAC: ", hex.EncodeToString(RootPreviousHmac), " CurrentHMAC: ", hex.EncodeToString(CurrentRootHmac), "\n")
		err = errors.New("Block is corrupted")
		return 0, err
	} else {
		println("previous and current MAC verified: PreviousHMAC: ", hex.EncodeToString(RootPreviousHmac), " CurrentHMAC: ", hex.EncodeToString(CurrentRootHmac))
	}

	println("//************ Unmarshaling Root ****************")
	root := &Root{}
	json.Unmarshal(RootData, &root)
	//println("\nlets see what is in root", string(RootData))

	currentBlockIndex := StackPointer
	currentBytePosition := 0
	currentBlockIndex += 1

	blocksInFile := len(data) / configBlockSize

	println("// ************** Blocks needs to be appended", blocksInFile, "**************\n")

	for i := 0; i < blocksInFile; i++ {

		println("// ************ created new block and stored its data and its hmac in it *************")
		currentBlock := &Block{}
		currentBlock.Data = data[currentBytePosition : currentBytePosition+configBlockSize]
		currentBlock.Hmac = userlib.NewHMAC(currentBlock.Data).Sum(nil)

		println("// ************ Marshaled the block before encrypting *******************")
		MarshaledBlock, _ := json.Marshal(currentBlock)

		println("//************* Encryting Block using blockCFB key *******************")
		currentBlockCipher := make([]byte, userlib.BlockSize+len(MarshaledBlock))

		println("// ************ Generate Random IV for each newly create block **********")
		currentBlockIV := currentBlockCipher[:userlib.BlockSize]
		copy(currentBlockIV, userlib.RandomBytes(userlib.BlockSize))

		blockCipherIntermediate := userlib.CFBEncrypter(BlockCFBKey, currentBlockIV)
		blockCipherIntermediate.XORKeyStream(currentBlockCipher[userlib.BlockSize:], MarshaledBlock)

		println("// ************ Put encrypted block in root ****************")
		root.SIP2Block[currentBlockIndex] = currentBlockCipher

		currentBlockIndex += 1
		currentBytePosition += configBlockSize
	}

	StackTop = currentBlockIndex - 1

	println("//************ Now Marshal the root again to store back **************")
	MarshaledRoot, _ := json.Marshal(root)
	//println("************** let's see the roo situation after append is over.***************\n")
	//println(string(MarshaledRoot))

	println("//************ Calculate HMAC again for the modifed root **********")
	MarshaledRootHMAC := userlib.NewHMAC(MarshaledRoot).Sum(nil)
	//println(" ############# HMAC size: Verification ######", len(MarshaledRootHMAC))

	println("//************ HMAC of Marshaled root is appended ****************")
	MarshaledRootWithHmacBytes := make([]byte, len(MarshaledRootHMAC)+len(MarshaledRoot))
	copy(MarshaledRootWithHmacBytes[:len(MarshaledRootHMAC)], MarshaledRootHMAC)
	copy(MarshaledRootWithHmacBytes[len(MarshaledRootHMAC):], MarshaledRoot)

	println("// *********** Store file back in data store ****************")
	userlib.DatastoreSet(BlockIndexKey, MarshaledRootWithHmacBytes)
	println("// *********** New file size ===========> ", len(MarshaledRootWithHmacBytes), " \n")

	return StackTop, err

}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	println("// ************** generating key to fetch file info block *********** \n")
	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	println("// ************** accessing file info block store at location ; ", hex.EncodeToString(fileIndexHmac))
	fileinfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		println("// *********** File not found **********//\n")
		err = errors.New("File Not Found")
		return data, err
	} else {

		println("// ************* Decrypting FileInfo Block  ****************")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		println(" $$$$$$$$$$$$$  encrypted file info  length, ", len(fileinfoBlockEncrypted))
		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]
		println("// ************ Extracted the file iv to decrypt ********* ", hex.EncodeToString(fileIV))
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		println("//************* Unmarshaling file info block ******************")
		UnmarshaledFileInfo := &File{}
		json.Unmarshal(fileInfoBlockPlainText[userlib.BlockSize:], &UnmarshaledFileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		rootIndexKey := UnmarshaledFileInfo.RootIndexUUID.String()
		BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		StackPointer := UnmarshaledFileInfo.StackPointer
		println("Root is store at : ", rootIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		println("// ************ Accessing Root stored at :", rootIndexKey, "*********\n")
		rootWithHmac, ok := userlib.DatastoreGet(rootIndexKey)
		if !ok {
			err = errors.New("file not found")
			return data, err
		}

		//println("// ############### HMAC size verification ######### ", len(fileIndexHmac))
		MarshaledRootByteHmac := rootWithHmac[:len(fileIndexHmac)]
		MarshaledRootBytes := rootWithHmac[len(fileIndexHmac):]
		currentRootHmac := userlib.NewHMAC(MarshaledRootBytes).Sum(nil)

		println(" Both hmac: ", hex.EncodeToString(MarshaledRootByteHmac), " ", hex.EncodeToString(currentRootHmac))

		if !userlib.Equal(currentRootHmac, MarshaledRootByteHmac) {
			println("// ********* Root HMAC verification failed:  previous: ", hex.EncodeToString(MarshaledRootByteHmac), " current: ", hex.EncodeToString(currentRootHmac))
			err = errors.New("File block corrupted.")
			return data, err
		} else {
			println("// ********* previous and current HAMC for root is verified:  previous: ", hex.EncodeToString(MarshaledRootByteHmac), " current: ", hex.EncodeToString(currentRootHmac))

		}

		//println("Marshaled root length: ", string(MarshaledRootBytes))
		Root := &Root{}
		json.Unmarshal(MarshaledRootBytes, &Root)
		println("unmarshaled root : ", len(rootWithHmac))

		println("Requesting block from offset : ", offset)
		RequestedEncryptedBlock := Root.SIP2Block[offset]

		//firstblock := Root.SIP2Block[0]
		//secondBlock := Root.SIP2Block[1]
		//println("requested block IV 0", hex.EncodeToString(firstblock), " 1 ", hex.EncodeToString(secondBlock))

		//BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		println("BlockCCFB KEy:", hex.EncodeToString(BlockCFBKey))
		RequestedBlockDecrypted := make([]byte, len(RequestedEncryptedBlock))
		BlockIV := RequestedEncryptedBlock[:userlib.BlockSize]
		println("Block IV to decrypt: ", hex.EncodeToString(BlockIV))
		BlockCipherText := userlib.CFBDecrypter(BlockCFBKey, BlockIV)
		BlockCipherText.XORKeyStream(RequestedBlockDecrypted[userlib.BlockSize:], RequestedEncryptedBlock[userlib.BlockSize:])

		Block := &Block{}
		json.Unmarshal(RequestedBlockDecrypted[userlib.BlockSize:], &Block)
		//println("Marshaled root data: ", string(RequestedBlockDecrypted[userlib.BlockSize:]))
		println("Hmac: ", hex.EncodeToString(Block.Hmac))
		data = Block.Data

	}

	return data, err
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	println("// ************** generating key to fetch file info block *********** \n")
	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	println("// ************** accessing file info block store at location ; ", hex.EncodeToString(fileIndexHmac))
	fileinfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		println("// *********** File not found **********//\n")
		err = errors.New("File Not Found")
		return msgid, err
	} else {

		println("// ************* Decrypting FileInfo Block  ****************")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		println(" $$$$$$$$$$$$$  encrypted file info  length, ", len(fileinfoBlockEncrypted))
		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]
		println("// ************ Extracted the file iv to decrypt ********* ", hex.EncodeToString(fileIV))
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		println("//************* Unmarshaling file info block ******************")
		UnmarshaledFileInfo := &File{}
		json.Unmarshal(fileInfoBlockPlainText[userlib.BlockSize:], &UnmarshaledFileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		rootIndexKey := UnmarshaledFileInfo.RootIndexUUID.String()
		BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		StackPointer := UnmarshaledFileInfo.StackPointer
		println("Root is store at : ", rootIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		println("// \n************** creating share file record ************ \n")
		SharingInfo := &sharingRecord{}
		SharingInfo.RootUUIDKey = UnmarshaledFileInfo.RootIndexUUID
		SharingInfo.BlockCFBKey = UnmarshaledFileInfo.BlockCFBKey
		SharingInfo.StackPointer = UnmarshaledFileInfo.StackPointer

		MarshaledSharingRecord, _ := json.Marshal(SharingInfo)

		println("//\n ********* Getting Recievers private key from the data store ************\n")

		recipientPublicKey, ok := userlib.KeystoreGet(recipient)
		marshaledPublickey, _ := json.Marshal(recipientPublicKey)
		if !ok {
			println("Public key of recipient not found")
		}

		println("Found public key of the recipient : ", hex.EncodeToString(marshaledPublickey))

		println("// \n Encrypting and signing message with RSA keys *********** \n")
		EncryptedMessage, _ := userlib.RSAEncrypt(&recipientPublicKey, MarshaledSharingRecord, []byte("sharingTag"))
		SignedMessage, _ := userlib.RSASign(&userdata.RSAPrivKey, EncryptedMessage)

		message := &message{}
		message.EncryptedMessage = EncryptedMessage
		message.Sign = SignedMessage

		MarshaledMessage, _ := json.Marshal(message)

		println("// *********** Encoded signed message to string for sharing ********** \n")
		msgid = hex.EncodeToString(MarshaledMessage)
		println(" \n*********** ", msgid, "************** \n")

	}

	return msgid, err
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {

	println("\n ************** Received followin message from sender ************* \n")
	println(msgid)

	println("// \n *************** Decoding string back to signed message and encrypted message  ********** \n")
	messageID := &message{}
	message, _ := hex.DecodeString(msgid)
	json.Unmarshal(message, &messageID)

	EncryptedMessage := messageID.EncryptedMessage
	SignedMessage := messageID.Sign

	senderPublicKey, _ := userlib.KeystoreGet(sender)
	println("// \n *************** Verifying sender *************** \n")
	err = userlib.RSAVerify(&senderPublicKey, EncryptedMessage, SignedMessage)
	if err != nil {
		println("Sign is not verified")
	} else {
		println("sign is verified. proceed with decryption.")
	}

	println("// \n ************** Dercypting message to get marshaled message **********\n")
	DecryptedMessage, err := userlib.RSADecrypt(&userdata.RSAPrivKey, EncryptedMessage, []byte("sharingTag"))
	if err != nil {
		println("\n ************ Decryption failed ************** \n")
	}

	println("// \n ************** Unmarshaling the message **********\n")
	sharedRecord := &sharingRecord{}
	json.Unmarshal(DecryptedMessage, &sharedRecord)

	println("// \n *********** Creating fileInfo Block for receiver ********\n")
	FileInfo := &File{}
	FileInfo.RootIndexUUID = sharedRecord.RootUUIDKey
	FileInfo.BlockCFBKey = sharedRecord.BlockCFBKey
	FileInfo.StackPointer = sharedRecord.StackPointer
	println("Root is store at : ", sharedRecord.RootUUIDKey.String())
	println("BlockCFB to decrypt the block is: ", hex.EncodeToString(sharedRecord.BlockCFBKey))
	println("Blocks stored sofar: ", sharedRecord.StackPointer+1)

	println("// \n *********** Create location index to store file info reciever **********\n")
	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexHmacString := string(fileIndexHmac)

	println("//\n ********** file will be store at this location ********* ", hex.EncodeToString(fileIndexHmac), " \n")

	println("// \n ********* marshaling file info before storing ******* \n")
	marshaledFileInfo, _ := json.Marshal(FileInfo)

	println("// \n ******** Encrypt File Info with receivers CFB file Key ************ \n")
	FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

	fileCipherText := make([]byte, userlib.BlockSize+len(marshaledFileInfo))
	fileiv := fileCipherText[:userlib.BlockSize]
	copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

	println("// ****************Receiver file IV ************** ", hex.EncodeToString(fileiv))

	//Encrypting file info
	fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
	fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], marshaledFileInfo)

	userlib.DatastoreSet(fileIndexHmacString, fileCipherText)
	println("// \n ********** File Info stored at location :, ", hex.EncodeToString(fileIndexHmac), " \n")

	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	println("//\n ***************  Generate File info Block Index ************\n")
	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	println("// \n ************ Fetch FileInfo present at location : ********* ", hex.EncodeToString(fileIndexHmac))
	fileInfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		println("\n file not found \n")
	} else {

		println("//\n ************* Decrypting FileInfo Block  **************** \n")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		println("// \n************ Generate new BlockCFBKey to Re-Encrypt each block again with new key  *********\n")
		newBlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)

		println("//\n************* Unmarshaling file info block ******************\n")
		FileInfo := &File{}
		json.Unmarshal(fileInfoBlockPlainText[userlib.BlockSize:], &FileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		BlockIndexKey := FileInfo.RootIndexUUID.String()
		BlockCFBKey := FileInfo.BlockCFBKey
		StackPointer := FileInfo.StackPointer
		println("Root is store at : ", BlockIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		DecrypteAndEncryptAgain(fileIndex, FileInfo.RootIndexUUID, FileInfo.BlockCFBKey, FileInfo.StackPointer, newBlockCFBKey)

		println("// \n **************** setting new details in the file again. **************** \n")
		FileInfo.BlockCFBKey = newBlockCFBKey

		newlyMarshaledFileInfo, _ := json.Marshal(FileInfo)

		println("// **************** file info block IV ************** ", hex.EncodeToString(fileIV))
		fileCipherText := make([]byte, userlib.BlockSize+len(newlyMarshaledFileInfo))
		copy(fileCipherText[:userlib.BlockSize], fileIV)
		fileCipherT := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherT.XORKeyStream(fileCipherText[userlib.BlockSize:], newlyMarshaledFileInfo)

		userlib.DatastoreSet(fileIndexString, fileCipherText)

	}

	return err
}

func DecrypteAndEncryptAgain(fileIndex []byte, RootIndexUUID uuid.UUID, oldBlockCFBKey []byte, StackPointer int, newBlockCFBKey []byte) (err error) {

	println("// \n ********** Fetch Root present at RootIndexUUID at : ************* ", RootIndexUUID.String(), "\n")

	MarshaledRootWithHmac, ok := userlib.DatastoreGet(RootIndexUUID.String())
	if !ok {
		println("\nRoot not found \n")
		err = errors.New("Root not found")
		return err
	} else {

		fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
		RootPreviousHmac := MarshaledRootWithHmac[:len(fileIndexHmac)]
		RootData := MarshaledRootWithHmac[len(fileIndexHmac):]
		CurrentRootHmac := userlib.NewHMAC(RootData).Sum(nil)

		if !userlib.Equal(RootPreviousHmac, CurrentRootHmac) {
			println("\nThere is some issue with  MAC : PreviousHMAC: ", hex.EncodeToString(RootPreviousHmac), " CurrentHMAC: ", hex.EncodeToString(CurrentRootHmac), "\n")
			err = errors.New("Block is corrupted")
			return err
		} else {
			println("previous and current MAC verified: PreviousHMAC: ", hex.EncodeToString(RootPreviousHmac), " CurrentHMAC: ", hex.EncodeToString(CurrentRootHmac))
		}

		println("//************ Unmarshaling Root ****************")
		root := &Root{}
		json.Unmarshal(RootData, &root)

		println("New Block Key Generated  ", hex.EncodeToString(newBlockCFBKey))

		ExistingBlocksInFile := StackPointer + 1

		for i := 0; i < ExistingBlocksInFile; i++ {
			if root.SIP2Block[i] != nil {
				println(" Processing block : ", i)

				BlockToDecrypt := root.SIP2Block[i]
				println("// ************* Decrypt with previous CFB key and IV: ******** ", hex.EncodeToString(oldBlockCFBKey), "\n")
				BlockToEncrypt := make([]byte, len(BlockToDecrypt))
				BlockIV := BlockToDecrypt[:userlib.BlockSize]

				BlockCipherText := userlib.CFBDecrypter(oldBlockCFBKey, BlockIV)
				BlockCipherText.XORKeyStream(BlockToEncrypt[userlib.BlockSize:], BlockToDecrypt[userlib.BlockSize:])

				println("// \n*********** Decryption done for block , ", i, "   ====== > Encrypting it with new blockCFBKey  *******, ", hex.EncodeToString(newBlockCFBKey), "\n")
				EncryptedBlock := make([]byte, len(BlockToEncrypt))
				newBlockIV := EncryptedBlock[:userlib.BlockSize]
				copy(newBlockIV, userlib.RandomBytes(userlib.BlockSize))

				BlockCipherT := userlib.CFBEncrypter(newBlockCFBKey, newBlockIV)
				BlockCipherT.XORKeyStream(EncryptedBlock[userlib.BlockSize:], BlockToEncrypt[userlib.BlockSize:])

				println("\n********* Block :", i, " Re-Encryption Over ********** \n")
				root.SIP2Block[i] = EncryptedBlock

			}
		}

		println("//\n ********** remarshal root  ************** \n")
		newlyMarshaledRoot, _ := json.Marshal(root)

		newlyMarshaledRootHMAC := userlib.NewHMAC(newlyMarshaledRoot).Sum(nil)

		println("//************ HMAC of Marshaled root is appended ****************")
		MarshaledRootWithHmacBytes := make([]byte, len(newlyMarshaledRootHMAC)+len(newlyMarshaledRoot))
		copy(MarshaledRootWithHmacBytes[:len(newlyMarshaledRootHMAC)], newlyMarshaledRootHMAC)
		copy(MarshaledRootWithHmacBytes[len(newlyMarshaledRootHMAC):], newlyMarshaledRoot)

		RootIndexKey := RootIndexUUID.String()
		println("// \n ************ Encrypted Root Stored Back at location :  ****************** ")
		userlib.DatastoreSet(RootIndexKey, MarshaledRootWithHmacBytes)

	}

	return err
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {

	println("*******Inside inituser*********\n")

	//User HMAC to local user details
	if username == "" || password == "" {
		err = errors.New("Username and Password are mandatory fields")
	} else {
		uspass := []byte(username + password)
		userHMAC := userlib.NewHMAC([]byte(uspass))
		HMACKeyString := string(userHMAC.Sum(nil))
		HMACKey := userHMAC.Sum(nil)

		argonKey := userlib.Argon2Key([]byte(username), []byte(password), 16)

		println("Userkey HMAC length: ", len(HMACKey))

		returnedbytes, _ := userlib.DatastoreGet("testkey")
		println("len : ", len(returnedbytes))

		RSAPrivKey, _ := userlib.GenerateRSAKey()

		userdataptr = &User{}
		userdataptr.Username = username
		userdataptr.Password = password
		userdataptr.RSAPrivKey = *RSAPrivKey
		//Convert userdata to bytes
		marshaledData, _ := json.Marshal(userdataptr)

		//Initailize empty cipherText and IV
		cipherText := make([]byte, userlib.BlockSize+len(marshaledData))
		iv := cipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))

		//Encrypting plaintext using HMACKey and iv
		cipher := userlib.CFBEncrypter(argonKey, iv)
		cipher.XORKeyStream(cipherText[userlib.BlockSize:], marshaledData)

		userlib.DatastoreSet(HMACKeyString, cipherText)
		userlib.KeystoreSet(username, RSAPrivKey.PublicKey)

	}
	return userdataptr, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	println("*******Inside GetUser*********\n")

	//User HMAC to local user details
	uspass := []byte(username + password)
	userHMAC := userlib.NewHMAC(uspass)
	HMACKeyString := string(userHMAC.Sum(nil))
	//HMACKey := userHMAC.Sum(nil)

	argonKey := userlib.Argon2Key([]byte(username), []byte(password), 16)

	encryptedText, ok := userlib.DatastoreGet(HMACKeyString)
	if !ok {
		err = errors.New("User does not exists")
	} else {

		plainText := make([]byte, len(encryptedText))
		iv := encryptedText[:userlib.BlockSize]
		cipherText := userlib.CFBDecrypter(argonKey, iv)
		cipherText.XORKeyStream(plainText[userlib.BlockSize:], encryptedText[userlib.BlockSize:])

		json.Unmarshal(plainText[userlib.BlockSize:], &userdataptr)

	}
	return userdataptr, err
}
