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
	userDetails, _ := InitUser("mani", "pass")
	secondUser, _ := InitUser("mani2", "pass")
	thirdUSer, _ := InitUser("mani3", "pass")

	println("All three users:", userDetails.Username, " ", secondUser.Username, " ", thirdUSer.Username)

	// Use this for testing purpose
	data1 := userlib.RandomBytes(4096)
	fileError := userDetails.StoreFile("filename1", data1)
	if fileError != nil {
		println("**** Unable to store file ****", fileError.Error())
	}

	data4 := userlib.RandomBytes(4096 * 799)
	AppendFileError2 := userDetails.AppendFile("filename1", data4)
	if AppendFileError2 != nil {
		println("Something went wrong while appending to the file.")
	}

	// msgid2, _ := userDetails.ShareFile("filename1", "mani2")
	// _ = secondUser.ReceiveFile("filename2", "mani", msgid2)

	// data3 := userlib.RandomBytes(4096 * 3)
	// AppendFileError := secondUser.AppendFile("filename2", data3)
	// if AppendFileError != nil {
	// 	println("Something went wrong while appending to the file.")
	// }

	// shareerr := userDetails.RevokeFile("filename1")
	// if shareerr != nil {
	// 	println("you dont have access to revoke this file")
	// } else {
	// 	println("revoke successfull")
	// }

	// data4 := userlib.RandomBytes(4096)
	// sherr := secondUser.AppendFile("filename2", data4)
	// if sherr != nil {
	// 	println("file not found ")
	// }

	// data5
	// if !userlib.Equal(data5, data4) {
	// 	println("data 5 data corrupted")
	// } else {
	// 	println("data 5 is not corrupted")
	// }

	// erred := userDetails.ReceiveFile("filename1", "mani2", msdid2)
	// if erred != nil {
	// 	println("could not receive file")
	// }

	// data4 := userlib.RandomBytes(4096)
	// AppendFileError2 := userDetails.AppendFile("filename1", data4)
	// if AppendFileError2 != nil {
	// 	println("Something went wrong while appending to the file.")
	// }

	// data5, _ := secondUser.LoadFile("filename2", 4)

	// if !userlib.Equal(data5, data4) {
	// 	println("data 5 data corrupted")
	// } else {
	// 	println("data 5 is not corrupted")
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
	SIP2Block [1000][]byte
	Top       int
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

	//println("Length of the bytes given : ", len(data), " Blocks in file: ", len(data)/configBlockSize)

	if (len(data) % configBlockSize) != 0 {
		err = errors.New("File is not a multiple fo file size\n")
		return err
	} else {

		//Generating file information block index.
		fileIndex := []byte(userdata.Username + filename)
		fileIndexHmac := userlib.NewHMAC(fileIndex)
		fileIndexHmacString := string(fileIndexHmac.Sum(nil))
		println("// ************* File info stored at : ", hex.EncodeToString(fileIndexHmac.Sum(nil)))
		rootKeyUUID := bytesToUUID(userlib.RandomBytes(16))

		fileInfoBlock := &File{}
		root := &Root{}

		fileInfoBlock.RootIndexUUID = rootKeyUUID

		blocksInFile := len(data) / configBlockSize

		//Generate Block CFB encryption and decryption key.
		BlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)
		//Generating File CFB
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		//Setting the actual data in the block with its calculated hmac
		//************ Starting block encryption ************
		block := &Block{}
		block.Data = data[:configBlockSize]
		//block.Hmac = userlib.NewHMAC(block.Data).Sum(nil)
		block.Hmac = createHMAC(BlockCFBKey, block.Data)

		//println("Block Data: ", hex.EncodeToString(block.Data))

		MarshaledBlockData, err1 := json.Marshal(block)
		if err1 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}
		//println("Marshal of block : ", 0, " ", string(MarshaledBlockData))

		//println("Length of Marshaled data: ", string(MarshaledBlockData))
		println("Hmac: ", hex.EncodeToString(block.Hmac))

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
		root.SIP2Block[currentBlockIndex] = blockCipherText
		root.Top = 0
		currentBlockIndex += 1

		MarshaledRoot, err2 := json.Marshal(root)
		if err2 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}
		println("length Root Marshaled ", len(MarshaledRoot))

		//rootHMAC := userlib.NewHMAC(MarshaledRoot)
		//rootHMacByte := rootHMAC.Sum(nil)
		//println("******* Hmac Length : ", hex.EncodeToString(rootHMacByte))
		//rootHMacByte := createHMAC(FileInfoCFBKey, MarshaledRoot)

		rootHMacByte := createHMAC(BlockCFBKey, MarshaledRoot)

		rootWithHmac := make([]byte, 32+len(MarshaledRoot))
		copy(rootWithHmac[:32], rootHMacByte)
		copy(rootWithHmac[32:], MarshaledRoot)
		//println("length of the root before storing blockcipher: ", len(rootWithHmac))

		userlib.DatastoreSet(rootKeyUUID.String(), rootWithHmac)
		println("File Stored at : ", rootKeyUUID.String())

		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		fileInfoBlock.BlockCFBKey = BlockCFBKey
		fileInfoBlock.StackPointer = 0 //len(data)/configBlockSize

		MarhsaledFile, err3 := json.Marshal(fileInfoBlock)
		if err3 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}

		FileInfoHMAC := createHMAC(fileIndex, MarhsaledFile)
		MarshaledFileWithHMAC := make([]byte, 32+len(MarhsaledFile))

		println("hAMC of file info ", hex.EncodeToString(FileInfoHMAC))

		copy(MarshaledFileWithHMAC[:32], FileInfoHMAC)
		copy(MarshaledFileWithHMAC[32:], MarhsaledFile)

		fileCipherText := make([]byte, userlib.BlockSize+len(MarshaledFileWithHMAC))
		fileiv := fileCipherText[:userlib.BlockSize]
		copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

		println("// **************** file iv ************** ", hex.EncodeToString(fileiv))

		//Encrypting file info
		fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
		fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], MarshaledFileWithHMAC)

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

	println("********************************************************")
	println("********************************************************")
	println("****************Appending Block*********************")
	println("********************************************************")
	println("********************************************************")

	if filename == "" || len(data)%configBlockSize != 0 {
		err = errors.New("Given data is not a multiple of block size")
		return err
	}

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	println("// ************* File info stored at : ", hex.EncodeToString(fileIndexHmac))
	fileInfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		println("\nFile not found \n")
		err = errors.New("File not found")
		return err
	} else {

		println("//\n ************* Decrypting FileInfo Block  ****************\n")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		println("File info CFB key append", hex.EncodeToString(FileInfoCFBKey))

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		println("File IV while appending: ", hex.EncodeToString(fileIV))

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		MarhshaledFileWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]

		fileHMAC := MarhshaledFileWithHMAC[:32]
		MarshaledFile := MarhshaledFileWithHMAC[32:]

		currentFileInfoHMAC := createHMAC(fileIndex, MarshaledFile)

		if !userlib.Equal(fileHMAC, currentFileInfoHMAC) {
			err = errors.New("File Information is tampered")
			return err
		} else {
			println("hAMC of file ifo verified: ", hex.EncodeToString(fileHMAC))
		}

		println("//\n************* Unmarshaling file info block ******************\n")
		FileInfo := &File{}
		json.Unmarshal(MarshaledFile, &FileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		BlockIndexKey := FileInfo.RootIndexUUID.String()
		BlockCFBKey := FileInfo.BlockCFBKey
		StackPointer := FileInfo.StackPointer
		println("Root is store at : ", BlockIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		println("//\n*************** Calling Encrypt block and store function *********** \n")
		StackPointer, fileErr := EncryptBlockAndStore(BlockIndexKey, BlockCFBKey, StackPointer, data, fileIndexHmac, FileInfoCFBKey)
		if fileErr != nil {
			err = errors.New("Failed to append")
			return err
		}
		println("// **************** Blocks currently present on file ==========> ", StackPointer+1, " \n")

		println("//\n************ update file info block agan with latest stack pointer ************\n")
		FileInfo.StackPointer = StackPointer

		println("// *********** Marshal file info again to store ************")
		marshaledFileInfoAfterUpdate, err4 := json.Marshal(FileInfo)
		if err4 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}

		//FileInfoHMAC := userlib.NewHMAC(marshaledFileInfoAfterUpdate).Sum(nil)
		FileInfoHMAC := createHMAC(fileIndex, marshaledFileInfoAfterUpdate)
		MarshaledFileWithHMAC := make([]byte, 32+len(marshaledFileInfoAfterUpdate))

		copy(MarshaledFileWithHMAC[:32], FileInfoHMAC)
		copy(MarshaledFileWithHMAC[32:], marshaledFileInfoAfterUpdate)

		println("//*********** Encrypt fileInfo again ****************")
		FileInfoCipher := make([]byte, userlib.BlockSize+len(MarshaledFileWithHMAC))
		copy(FileInfoCipher[:userlib.BlockSize], fileIV)
		fileCipherAgain := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherAgain.XORKeyStream(FileInfoCipher[userlib.BlockSize:], MarshaledFileWithHMAC)

		println("// ********** Store encrypted file info back again in datatore ***********", hex.EncodeToString(fileIndexHmac))
		userlib.DatastoreSet(fileIndexString, FileInfoCipher)
		println(" $$$$$$$$$$$$$  encrypted file info  length, ", len(FileInfoCipher))

		println("\nFileSize after appending the file:", len(FileInfoCipher), "\n")

	}

	return err
}

func EncryptBlockAndStore(RootIndexKey string, BlockCFBKey []byte, StackPointer int, data []byte, fileIndexHmac []byte, fileInfoCFBKey []byte) (StackTop int, err error) {

	println("// ************ Fetching Root First ***************")
	MarshaledRootWithHmac, ok := userlib.DatastoreGet(RootIndexKey)
	if !ok {
		err = errors.New("File not found ")
		return 0, err
	}

	println("// \n*********** Verifying HMAC *****************\n")
	RootPreviousHmac := MarshaledRootWithHmac[:32]
	RootData := MarshaledRootWithHmac[32:]
	//CurrentRootHmac := createHMAC(fileInfoCFBKey, RootData)
	CurrentRootHmac := createHMAC(BlockCFBKey, RootData)

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

	currentBlockIndex := root.Top
	currentBytePosition := 0
	currentBlockIndex += 1

	blocksInFile := len(data) / configBlockSize

	println("// ************** Blocks needs to be appended", blocksInFile, "**************\n")

	for i := 0; i < blocksInFile; i++ {

		println("// ************ created new block and stored its data and its hmac in it *************")
		currentBlock := &Block{}
		currentBlock.Data = data[currentBytePosition : currentBytePosition+configBlockSize]
		currentBlock.Hmac = createHMAC(BlockCFBKey, currentBlock.Data)

		println("// ************ Marshaled the block before encrypting *******************")
		MarshaledBlock, err5 := json.Marshal(currentBlock)
		if err5 != nil {
			err = errors.New("Unamrshaling failed")
			return 0, err
		}

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
	root.Top = currentBlockIndex - 1

	println("//************ Now Marshal the root again to store back **************")
	MarshaledRoot, err6 := json.Marshal(root)
	if err6 != nil {
		err = errors.New("Unamrshaling failed")
		return 0, err
	}
	//println("************** let's see the roo situation after append is over.***************\n")
	//println(string(MarshaledRoot))

	println("//************ Calculate HMAC again for the modifed root **********")
	//MarshaledRootHMAC := createHMAC(fileInfoCFBKey, MarshaledRoot)
	MarshaledRootHMAC := createHMAC(BlockCFBKey, MarshaledRoot)

	//println(" ############# HMAC size: Verification ######", len(MarshaledRootHMAC))

	println("//************ HMAC of Marshaled root is appended ****************")
	MarshaledRootWithHmacBytes := make([]byte, 32+len(MarshaledRoot))
	copy(MarshaledRootWithHmacBytes[:32], MarshaledRootHMAC)
	copy(MarshaledRootWithHmacBytes[32:], MarshaledRoot)

	println("// *********** Store file back in data store ****************")
	userlib.DatastoreSet(RootIndexKey, MarshaledRootWithHmacBytes)
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
		return nil, err
	} else {

		println("//\n ************* Decrypting FileInfo Block  ****************")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		println("//\n *************  encrypted file info  length, ", len(fileinfoBlockEncrypted))
		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]

		println("// \n ************ Extracted the file iv to decrypt ********* ", hex.EncodeToString(fileIV))
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		println("//************* Unmarshaling file info block ******************")

		fileInfoWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]
		filePreviousHMAC := fileInfoWithHMAC[:32]
		fileInfomarshaled := fileInfoWithHMAC[32:]

		fileCurrentHMAC := createHMAC(fileIndex, fileInfomarshaled)

		println("file HMAC verified in load file : ", hex.EncodeToString(fileCurrentHMAC), hex.EncodeToString(filePreviousHMAC))

		if !userlib.Equal(filePreviousHMAC, fileCurrentHMAC) {
			println("Failed to verify file info HAMC in load file: ")
			err = errors.New("File not found")
			return nil, err
		} else {
			println("file HMAC verified in load file : ", hex.EncodeToString(fileCurrentHMAC))
		}

		UnmarshaledFileInfo := &File{}
		json.Unmarshal(fileInfomarshaled, &UnmarshaledFileInfo)

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
			return nil, err
		}

		println("// ############### HMAC size verification ######### ", len(fileIndexHmac))
		currentHMAC := rootWithHmac[:32]
		MarshaledRootBytes := rootWithHmac[32:]
		//currentRootHmac := createHMAC(FileInfoCFBKey, MarshaledRootBytes)
		currentRootHmac := createHMAC(BlockCFBKey, MarshaledRootBytes)

		println(" Both hmac: ", hex.EncodeToString(currentRootHmac), " ", hex.EncodeToString(currentHMAC))

		if !userlib.Equal(currentRootHmac, currentHMAC) {
			//println("// ********* Root HMAC verification failed:  previous: ", hex.EncodeToString(MarshaledRootByteHmac), " current: ", hex.EncodeToString(currentRootHmac))
			err = errors.New("File block corrupted.")
			return nil, err
		} else {
			println("// ********* previous and current HAMC for root is verified:  previous: ", hex.EncodeToString(currentHMAC), " current: ", hex.EncodeToString(currentRootHmac))

		}

		//println("Marshaled root length: ", string(MarshaledRootBytes))
		Root := &Root{}
		json.Unmarshal(MarshaledRootBytes, &Root)
		//println("unmarshaled root : ", len(rootWithHmac))

		if offset < 0 || offset > Root.Top {
			err = errors.New("offset not in range")
			return nil, err
		}

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

		block := &Block{}
		json.Unmarshal(RequestedBlockDecrypted[userlib.BlockSize:], &block)
		//println("Marshaled root data: ", string(RequestedBlockDecrypted[userlib.BlockSize:]))
		println("Hmac: ", hex.EncodeToString(block.Hmac))

		currentBlockHMAC := createHMAC(BlockCFBKey, block.Data)
		previousBlockHMAC := block.Hmac

		if !userlib.Equal(currentBlockHMAC, previousBlockHMAC) {
			err = errors.New("Data corrupted:!")
			return nil, err
		}

		data = block.Data

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

		println(" *************  encrypted file info  length, ", len(fileinfoBlockEncrypted))
		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]
		println("// ************ Extracted the file iv to decrypt ********* ", hex.EncodeToString(fileIV))
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		MarhshaledFileWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]

		fileHMAC := MarhshaledFileWithHMAC[:32]
		MarshaledFile := MarhshaledFileWithHMAC[32:]

		currentFileInfoHMAC := createHMAC(fileIndex, MarshaledFile)

		println("Sharing record HMAC : ", hex.EncodeToString(fileHMAC), hex.EncodeToString(currentFileInfoHMAC))
		if !userlib.Equal(fileHMAC, currentFileInfoHMAC) {
			println("File Info Block Didnot match")
			err = errors.New("File Information is tampered")
			return "", err
		}

		println("//************* Unmarshaling file info block ******************")
		UnmarshaledFileInfo := &File{}
		json.Unmarshal(MarshaledFile, &UnmarshaledFileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		rootIndexKey := UnmarshaledFileInfo.RootIndexUUID.String()
		BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		StackPointer := UnmarshaledFileInfo.StackPointer
		println("Root is store at : ", rootIndexKey)
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		println("Check if root if present at the given location")
		_, ok := userlib.DatastoreGet(rootIndexKey)
		if !ok {
			println("could not find the root")
			err = errors.New("Could not find the root")
			return "", err
		}

		println("// \n************** creating share file record ************ \n")
		SharingInfo := &sharingRecord{}
		SharingInfo.RootUUIDKey = UnmarshaledFileInfo.RootIndexUUID
		SharingInfo.BlockCFBKey = UnmarshaledFileInfo.BlockCFBKey
		SharingInfo.StackPointer = UnmarshaledFileInfo.StackPointer

		MarshaledSharingRecord, err7 := json.Marshal(SharingInfo)
		if err7 != nil {
			err = errors.New("Unamrshaling failed")
			return "", err
		}

		println("//\n ********* Getting Recievers private key from the data store ************\n")

		recipientPublicKey, ok := userlib.KeystoreGet(recipient)
		//marshaledPublickey, _ := json.Marshal(recipientPublicKey)
		if !ok {
			println("Public key of recipient not found")
			err = errors.New("Public key of recipient not found")
			return "", err
		}

		//println("Found public key of the recipient : ", hex.EncodeToString(marshaledPublickey))

		println("// \n Encrypting and signing message with RSA keys *********** \n")
		EncryptedMessage, encryptError := userlib.RSAEncrypt(&recipientPublicKey, MarshaledSharingRecord, []byte("sharingTag"))
		if encryptError != nil {
			err = errors.New("Unable to enrcypt file")
			return "", err
		}
		SignedMessage, signError := userlib.RSASign(&userdata.RSAPrivKey, EncryptedMessage)
		if signError != nil {
			err = errors.New("Unable to sign file")
			return "", err
		}

		message := &message{}
		message.EncryptedMessage = EncryptedMessage
		message.Sign = SignedMessage

		MarshaledMessage, err8 := json.Marshal(message)
		if err8 != nil {
			err = errors.New("Unamrshaling failed")
			return "", err
		}
		println("// *********** Encoded signed message to string for sharing ********** \n")
		msgid = hex.EncodeToString(MarshaledMessage)
		//println(" \n*********** Messge ID ", msgid, "************** \n")
		//println(" \n*********** Marshaled Message: ", MarshaledMessage, "************** \n")

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
	//println(" \n*********** Messge ID ", msgid, "************** \n")

	println("// \n *************** Decoding string back to signed message and encrypted message  ********** \n")

	messageID := &message{}
	message, err9 := hex.DecodeString(msgid)
	if err9 != nil {
		err = errors.New("could not decode")
		return err
	}

	//println(" \n*********** Marshaled Message: ", message, "************** \n")
	json.Unmarshal(message, &messageID)

	EncryptedMessage := messageID.EncryptedMessage
	SignedMessage := messageID.Sign

	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		err = errors.New("Senders public key not found")
		return err
	}
	println("// \n *************** Verifying sender *************** \n")
	err = userlib.RSAVerify(&senderPublicKey, EncryptedMessage, SignedMessage)
	if err != nil {
		println("Sign is not verified")
		err = errors.New("Sign is not verified")
		return err
	} else {
		println("sign is verified. proceed with decryption.")
	}

	println("// \n ************** Dercypting message to get marshaled message **********\n")
	DecryptedMessage, err := userlib.RSADecrypt(&userdata.RSAPrivKey, EncryptedMessage, []byte("sharingTag"))
	if err != nil {
		println("\n ************ Decryption failed ************** \n")
		err = errors.New("Decryption Failed")
		return err
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
	marshaledFileInfo, err10 := json.Marshal(FileInfo)
	if err10 != nil {
		err = errors.New("Unamrshaling failed")
		return err
	}

	fileInfoHMAC := createHMAC(fileIndex, marshaledFileInfo)

	marshaledFileInfoWithHMAC := make([]byte, 32+len(marshaledFileInfo))
	copy(marshaledFileInfoWithHMAC[:32], fileInfoHMAC)
	copy(marshaledFileInfoWithHMAC[32:], marshaledFileInfo)

	println("// \n ******** Encrypt File Info with receivers CFB file Key ************ \n")
	FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

	fileCipherText := make([]byte, userlib.BlockSize+len(marshaledFileInfoWithHMAC))
	fileiv := fileCipherText[:userlib.BlockSize]
	copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

	println("// ****************Receiver file IV ************** ", hex.EncodeToString(fileiv))

	//Encrypting file info
	fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
	fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], marshaledFileInfoWithHMAC)

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
		err = errors.New("file not found")
		return err
	} else {

		println("//\n ************* Decrypting FileInfo Block  **************** \n")
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		println("revoke file file IV: ", hex.EncodeToString(fileIV))

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		MarshaledFileInfoWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]
		previousFileHMAC := MarshaledFileInfoWithHMAC[:32]
		MarshaledFileInfo := MarshaledFileInfoWithHMAC[32:]

		currentHMAC := createHMAC(fileIndex, MarshaledFileInfo)
		println("File HMAC verification: ", hex.EncodeToString(currentHMAC), hex.EncodeToString(previousFileHMAC))

		if !userlib.Equal(currentHMAC, previousFileHMAC) {
			println("You dont have access to the file")
			err = errors.New("You dont have access to view this file")
			return err
		} else {
			println("File HMAC verified in revoke file")
		}

		println("// \n************ Generate new BlockCFBKey to Re-Encrypt each block again with new key  *********\n")
		newBlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)
		newRootKeyUUID := bytesToUUID(userlib.RandomBytes(16))

		println("newBlockCFB and newRootUUID location", hex.EncodeToString(newBlockCFBKey), newRootKeyUUID.String())

		println("//\n************* Unmarshaling file info block ******************\n")
		FileInfo := &File{}
		json.Unmarshal(MarshaledFileInfo, &FileInfo)

		println("//\n************* Extracting required details from file info Block *********\n")
		oldBlockIndexKey := FileInfo.RootIndexUUID.String()
		//BlockCFBKey := FileInfo.BlockCFBKey
		StackPointer := FileInfo.StackPointer

		decryptError := DecrypteAndEncryptAgain(newRootKeyUUID, fileIndex, FileInfo.RootIndexUUID, FileInfo.BlockCFBKey, FileInfo.StackPointer, newBlockCFBKey)
		if decryptError != nil {
			err = errors.New("you dont have access to change the file")
			return err
		}

		println("// \n **************** setting new details in the file again. **************** \n")
		FileInfo.BlockCFBKey = newBlockCFBKey
		FileInfo.RootIndexUUID = newRootKeyUUID
		println("Root is store at : ", FileInfo.RootIndexUUID.String())
		println("BlockCFB to decrypt the block is: ", hex.EncodeToString(FileInfo.BlockCFBKey))
		println("Blocks stored sofar: ", StackPointer+1)

		newlyMarshaledFileInfo, err11 := json.Marshal(FileInfo)
		if err11 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}

		newFileHMAC := createHMAC(fileIndex, newlyMarshaledFileInfo)

		newFileWithHMAC := make([]byte, 32+len(newlyMarshaledFileInfo))
		copy(newFileWithHMAC[:32], newFileHMAC)
		copy(newFileWithHMAC[32:], newlyMarshaledFileInfo)

		println("// **************** file info block IV ************** ", hex.EncodeToString(fileIV))
		fileCipherText := make([]byte, userlib.BlockSize+len(newFileWithHMAC))
		copy(fileCipherText[:userlib.BlockSize], fileIV)
		fileCipherT := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherT.XORKeyStream(fileCipherText[userlib.BlockSize:], newFileWithHMAC)

		userlib.DatastoreSet(fileIndexString, fileCipherText)

		println("Removing previous entries of root from the datastore")
		userlib.DatastoreDelete(oldBlockIndexKey)

	}

	return err
}

func DecrypteAndEncryptAgain(newRootKeyUUID uuid.UUID, fileIndex []byte, RootIndexUUID uuid.UUID, oldBlockCFBKey []byte, StackPointer int, newBlockCFBKey []byte) (err error) {

	println("// \n ********** Fetch Root present at RootIndexUUID at : ************* ", RootIndexUUID.String(), "\n")

	MarshaledRootWithHmac, ok := userlib.DatastoreGet(RootIndexUUID.String())
	if !ok {
		println("\nRoot not found \n")
		err = errors.New("Root not found")
		return err
	} else {

		RootPreviousHmac := MarshaledRootWithHmac[:32]
		RootData := MarshaledRootWithHmac[32:]
		CurrentRootHmac := createHMAC(oldBlockCFBKey, RootData)

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

		ExistingBlocksInFile := root.Top + 1

		for i := 0; i < ExistingBlocksInFile; i++ {
			if root.SIP2Block[i] != nil {
				println(" Processing block : ", i)

				BlockToDecrypt := root.SIP2Block[i]
				println("// ************* Decrypt with previous CFB key and IV: ******** ", hex.EncodeToString(oldBlockCFBKey), "\n")
				BlockToEncrypt := make([]byte, len(BlockToDecrypt))
				BlockIV := BlockToDecrypt[:userlib.BlockSize]
				//copy(BlockToEncrypt[:userlib.BlockSize], BlockIV)

				BlockCipherText := userlib.CFBDecrypter(oldBlockCFBKey, BlockIV)
				BlockCipherText.XORKeyStream(BlockToEncrypt[userlib.BlockSize:], BlockToDecrypt[userlib.BlockSize:])

				marshaledBlock := BlockToEncrypt[userlib.BlockSize:]

				tempBlock := &Block{}
				json.Unmarshal(marshaledBlock, &tempBlock)

				data := tempBlock.Data
				//previousHMAc := tempBlock.Hmac

				newHMAC := createHMAC(newBlockCFBKey, data)
				tempBlock.Hmac = newHMAC

				marshaledBlockWithNewHMAC, err12 := json.Marshal(tempBlock)
				if err12 != nil {
					err = errors.New("Unamrshaling failed")
					return err
				}

				println("// \n*********** Decryption done for block , ", i, "   ====== > Encrypting it with new blockCFBKey  *******, ", hex.EncodeToString(newBlockCFBKey), "\n")
				EncryptedBlock := make([]byte, userlib.BlockSize+len(marshaledBlockWithNewHMAC))
				newBlockIV := EncryptedBlock[:userlib.BlockSize]
				copy(newBlockIV, userlib.RandomBytes(userlib.BlockSize))

				println("Block IV for ", i, " ", hex.EncodeToString(newBlockIV))

				BlockCipherT := userlib.CFBEncrypter(newBlockCFBKey, newBlockIV)
				BlockCipherT.XORKeyStream(EncryptedBlock[userlib.BlockSize:], marshaledBlockWithNewHMAC)

				println("\n********* Block :", i, " Re-Encryption Over ********** \n")
				root.SIP2Block[i] = EncryptedBlock

			}
		}

		println("//\n ********** remarshal root  ************** \n")
		newlyMarshaledRoot, err13 := json.Marshal(root)
		if err13 != nil {
			err = errors.New("Unamrshaling failed")
			return err
		}

		println("//************ HMAC of Marshaled root is appended ****************")
		newlyMarshaledRootHMAC := createHMAC(newBlockCFBKey, newlyMarshaledRoot)
		newMarshaledRootWithHMAC := make([]byte, 32+len(newlyMarshaledRoot))
		copy(newMarshaledRootWithHMAC[:32], newlyMarshaledRootHMAC)
		copy(newMarshaledRootWithHMAC[32:], newlyMarshaledRoot)

		RootIndexKey := newRootKeyUUID.String()
		println("// \n ************ Encrypted Root Stored Back at location :  ****************** ")
		userlib.DatastoreSet(RootIndexKey, newMarshaledRootWithHMAC)

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

	//User HMAC to local user details
	if username == "" || password == "" {
		err = errors.New("Username and Password are mandatory fields")
		return nil, err
	} else {

		println("*******Inside inituser*********\n")
		uspass := []byte(username + password)
		userHMAC := userlib.NewHMAC([]byte(uspass))
		HMACKeyString := string(userHMAC.Sum(nil))

		_, ok := userlib.DatastoreGet(HMACKeyString)
		if ok {
			err = errors.New("User cannot be initilized again.")
			return nil, err
		}

		argonKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
		RSAPrivKey, err20 := userlib.GenerateRSAKey()
		if err20 != nil {
			err = errors.New("Generate key failed")
			return nil, err
		}

		userdataptr = &User{}
		userdataptr.Username = username
		userdataptr.Password = password
		userdataptr.RSAPrivKey = *RSAPrivKey

		//Convert userdata to bytes
		marshaledData, err15 := json.Marshal(userdataptr)
		if err15 != nil {
			err = errors.New("Unamrshaling failed")
			return nil, err
		}

		dataHMAC := createHMAC(uspass, marshaledData)
		marshaledDataWithHMAC := make([]byte, len(dataHMAC)+len(marshaledData))
		copy(marshaledDataWithHMAC[:len(dataHMAC)], dataHMAC)
		copy(marshaledDataWithHMAC[len(dataHMAC):], marshaledData)

		//Initailize empty cipherText and IV
		cipherText := make([]byte, userlib.BlockSize+len(marshaledDataWithHMAC))
		iv := cipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))

		//Encrypting plaintext using HMACKey and iv
		cipher := userlib.CFBEncrypter(argonKey, iv)
		cipher.XORKeyStream(cipherText[userlib.BlockSize:], marshaledDataWithHMAC)

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

	if username == "" || password == "" {
		err = errors.New("username and password cannot be empty")
		return nil, err
	} else {

		println("*******Inside GetUser*********\n")

		//User HMAC to local user details
		uspass := []byte(username + password)
		userHMAC := userlib.NewHMAC(uspass)
		HMACKeyString := string(userHMAC.Sum(nil))

		argonKey := userlib.Argon2Key([]byte(username), []byte(password), 16)

		encryptedText, ok := userlib.DatastoreGet(HMACKeyString)
		if !ok {
			err = errors.New("User does not exists")
			return nil, err
		} else {

			plainText := make([]byte, len(encryptedText))
			iv := encryptedText[:userlib.BlockSize]
			cipherText := userlib.CFBDecrypter(argonKey, iv)
			cipherText.XORKeyStream(plainText[userlib.BlockSize:], encryptedText[userlib.BlockSize:])

			marshaledDataWithHMAC := plainText[userlib.BlockSize:]
			previousHMAC := marshaledDataWithHMAC[:32]
			userData := marshaledDataWithHMAC[32:]

			currentHMAC := createHMAC(uspass, userData)

			if !userlib.Equal(currentHMAC, previousHMAC) {
				err = errors.New("data corrupted")
				return nil, err
			}

			json.Unmarshal(userData, &userdataptr)

		}
	}
	return userdataptr, err
}

func createHMAC(key []byte, data []byte) (hmac []byte) {

	mac := userlib.NewHMAC(key)
	mac.Write(data)
	return mac.Sum(nil)

}
