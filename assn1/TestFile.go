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

	userDetails, _ := InitUser("mani", "pass")

	println("Init User: ", userDetails.Username, userDetails.Password)

	secondUser, err := InitUser("mani2", "pass")

	if err != nil {
		print("error occcured")
	} else {
		println("Init User second: ", secondUser.Username, secondUser.Password)
	}

	getUser, err := GetUser("mani", "pass")
	if err != nil {
		println("datacrou")
	} else {
		println("user details: ", getUser.Username, getUser.Password)
	}

	//thirdUSer, _ := InitUser("mani3", "pass")

	secondUserFetchedDetails, err := GetUser(secondUser.Username, secondUser.Password)
	if err != nil {
		println("User does not exists")
	} else {
		println("Get User: ", secondUserFetchedDetails.Username, secondUserFetchedDetails.Password)
	}

	// Use this for testing purpose
	data1 := userlib.RandomBytes(4096)
	fileError := userDetails.StoreFile("filename1", data1)
	if fileError != nil {
		println("**** Unable to store file ****", fileError.Error())
	}

	data3 := userlib.RandomBytes(4096 * 2)
	AppendFileError := userDetails.AppendFile("filename1", data3)
	if AppendFileError != nil {
		println("Something went wrong while appending to the file.")
	}

	data2, _ := userDetails.LoadFile("filename1", 1)

	if !userlib.Equal(data3[:configBlockSize], data2) {
		println("data 2 data corrupted")
	} else {
		println("data 2 is not corrupted")
	}

	msgid2, _ := userDetails.ShareFile("filename1", "mani2")
	_ = secondUser.ReceiveFile("filename2", "mani", msgid2)

	data5, _ := secondUser.LoadFile("filename2", 2)

	if !userlib.Equal(data3[configBlockSize:], data5) {
		println("data 3 corrupted")
	} else {
		println("data 3 is not corrupted")
	}

	_ = userDetails.RevokeFile("filename1")

	data6, _ := secondUser.LoadFile("filename2", 2)

	if !userlib.Equal(data3[configBlockSize:], data6) {
		println("data 6 corrupted")
	} else {
		println("data 6 is not corrupted")
	}

	data7, _ := userDetails.LoadFile("filename1", 2)

	if !userlib.Equal(data3[configBlockSize:], data7) {
		println("data 7 corrupted")
	} else {
		println("data 7 is not corrupted")
	}

	data8, _ := secondUser.LoadFile("filename2", 0)

	if !userlib.Equal(data1, data8) {
		println("data 8 corrupted")
	} else {
		println("data 8 is not corrupted")
	}
	// data6, _ := thirdUSer.LoadFile("filename3", 1)

	// if !userlib.Equal(data6[:configBlockSize], data2) {
	// 	println("data 3 corrupted")
	// } else {
	// 	println("data 3 is not corrupted")
	// }

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

	if (len(data) % configBlockSize) != 0 {
		err = errors.New("File is not a multiple fo file size\n")
		return err
	} else {

		//Generating file information block index.
		fileIndex := []byte(userdata.Username + filename)
		fileIndexHmac := userlib.NewHMAC(fileIndex)
		fileIndexHmacString := string(fileIndexHmac.Sum(nil))
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

		MarshaledBlockData, _ := json.Marshal(block)

		//Encrypt file with above generated Block CFB
		blockCipherText := make([]byte, userlib.BlockSize+len(MarshaledBlockData))
		iv := blockCipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))

		blockCipher := userlib.CFBEncrypter(BlockCFBKey, iv)
		blockCipher.XORKeyStream(blockCipherText[userlib.BlockSize:], MarshaledBlockData)
		// ********* Block Encryption done ************

		currentBlockIndex := 0
		root.SIP2Block[currentBlockIndex] = blockCipherText
		currentBlockIndex += 1

		MarshaledRoot, _ := json.Marshal(root)

		rootHMacByte := createHMAC(BlockCFBKey, MarshaledRoot)

		rootWithHmac := make([]byte, 32+len(MarshaledRoot))
		copy(rootWithHmac[:32], rootHMacByte)
		copy(rootWithHmac[32:], MarshaledRoot)

		userlib.DatastoreSet(rootKeyUUID.String(), rootWithHmac)

		fileInfoBlock.BlockCFBKey = BlockCFBKey
		fileInfoBlock.StackPointer = 0 //len(data)/configBlockSize

		MarhsaledFile, _ := json.Marshal(fileInfoBlock)

		FileInfoHMAC := createHMAC(fileIndex, MarhsaledFile)
		MarshaledFileWithHMAC := make([]byte, 32+len(MarhsaledFile))

		copy(MarshaledFileWithHMAC[:32], FileInfoHMAC)
		copy(MarshaledFileWithHMAC[32:], MarhsaledFile)

		fileCipherText := make([]byte, userlib.BlockSize+len(MarshaledFileWithHMAC))
		fileiv := fileCipherText[:userlib.BlockSize]
		copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

		//Encrypting file info
		fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
		fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], MarshaledFileWithHMAC)

		userlib.DatastoreSet(fileIndexHmacString, fileCipherText)
		if blocksInFile > 1 {
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

	if filename == "" || len(data)%configBlockSize != 0 {
		err = errors.New("Given data is not a multiple of block size")
		return err
	}

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	fileInfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		err = errors.New("File not found")
		return err
	} else {

		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		MarhshaledFileWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]

		fileHMAC := MarhshaledFileWithHMAC[:32]
		MarshaledFile := MarhshaledFileWithHMAC[32:]

		currentFileInfoHMAC := createHMAC(fileIndex, MarshaledFile)

		if !userlib.Equal(fileHMAC, currentFileInfoHMAC) {
			err = errors.New("File Information is tampered")
			return err
		}

		FileInfo := &File{}
		json.Unmarshal(MarshaledFile, &FileInfo)

		BlockIndexKey := FileInfo.RootIndexUUID.String()
		BlockCFBKey := FileInfo.BlockCFBKey
		StackPointer := FileInfo.StackPointer

		StackPointer, _ = EncryptBlockAndStore(BlockIndexKey, BlockCFBKey, StackPointer, data, fileIndexHmac, FileInfoCFBKey)

		FileInfo.StackPointer = StackPointer

		marshaledFileInfoAfterUpdate, _ := json.Marshal(FileInfo)

		//FileInfoHMAC := userlib.NewHMAC(marshaledFileInfoAfterUpdate).Sum(nil)
		FileInfoHMAC := createHMAC(fileIndex, marshaledFileInfoAfterUpdate)
		MarshaledFileWithHMAC := make([]byte, 32+len(marshaledFileInfoAfterUpdate))

		copy(MarshaledFileWithHMAC[:32], FileInfoHMAC)
		copy(MarshaledFileWithHMAC[32:], marshaledFileInfoAfterUpdate)

		FileInfoCipher := make([]byte, userlib.BlockSize+len(MarshaledFileWithHMAC))
		copy(FileInfoCipher[:userlib.BlockSize], fileIV)
		fileCipherAgain := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherAgain.XORKeyStream(FileInfoCipher[userlib.BlockSize:], MarshaledFileWithHMAC)

		userlib.DatastoreSet(fileIndexString, FileInfoCipher)

	}

	return err
}

func EncryptBlockAndStore(RootIndexKey string, BlockCFBKey []byte, StackPointer int, data []byte, fileIndexHmac []byte, fileInfoCFBKey []byte) (StackTop int, err error) {

	MarshaledRootWithHmac, ok := userlib.DatastoreGet(RootIndexKey)
	if !ok {
		err = errors.New("File not found ")
		return 0, err
	}

	RootPreviousHmac := MarshaledRootWithHmac[:32]
	RootData := MarshaledRootWithHmac[32:]
	//CurrentRootHmac := createHMAC(fileInfoCFBKey, RootData)
	CurrentRootHmac := createHMAC(BlockCFBKey, RootData)

	if !userlib.Equal(RootPreviousHmac, CurrentRootHmac) {
		err = errors.New("Block is corrupted")
		return 0, err
	}

	root := &Root{}
	json.Unmarshal(RootData, &root)

	currentBlockIndex := StackPointer
	currentBytePosition := 0
	currentBlockIndex += 1

	blocksInFile := len(data) / configBlockSize

	for i := 0; i < blocksInFile; i++ {

		currentBlock := &Block{}
		currentBlock.Data = data[currentBytePosition : currentBytePosition+configBlockSize]
		currentBlock.Hmac = createHMAC(BlockCFBKey, currentBlock.Data)

		MarshaledBlock, _ := json.Marshal(currentBlock)

		currentBlockCipher := make([]byte, userlib.BlockSize+len(MarshaledBlock))

		currentBlockIV := currentBlockCipher[:userlib.BlockSize]
		copy(currentBlockIV, userlib.RandomBytes(userlib.BlockSize))

		blockCipherIntermediate := userlib.CFBEncrypter(BlockCFBKey, currentBlockIV)
		blockCipherIntermediate.XORKeyStream(currentBlockCipher[userlib.BlockSize:], MarshaledBlock)

		root.SIP2Block[currentBlockIndex] = currentBlockCipher

		currentBlockIndex += 1
		currentBytePosition += configBlockSize
	}

	StackTop = currentBlockIndex - 1

	MarshaledRoot, _ := json.Marshal(root)
	//MarshaledRootHMAC := createHMAC(fileInfoCFBKey, MarshaledRoot)
	MarshaledRootHMAC := createHMAC(BlockCFBKey, MarshaledRoot)

	MarshaledRootWithHmacBytes := make([]byte, 32+len(MarshaledRoot))
	copy(MarshaledRootWithHmacBytes[:32], MarshaledRootHMAC)
	copy(MarshaledRootWithHmacBytes[32:], MarshaledRoot)

	userlib.DatastoreSet(RootIndexKey, MarshaledRootWithHmacBytes)

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

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	fileinfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		err = errors.New("File Not Found")
		return nil, err
	} else {

		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]

		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		fileInfoWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]
		filePreviousHMAC := fileInfoWithHMAC[:32]
		fileInfomarshaled := fileInfoWithHMAC[32:]

		fileCurrentHMAC := createHMAC(fileIndex, fileInfomarshaled)

		if !userlib.Equal(filePreviousHMAC, fileCurrentHMAC) {
			err = errors.New("File not found")
			return nil, err
		}

		UnmarshaledFileInfo := &File{}
		json.Unmarshal(fileInfomarshaled, &UnmarshaledFileInfo)

		rootIndexKey := UnmarshaledFileInfo.RootIndexUUID.String()
		BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		StackPointer := UnmarshaledFileInfo.StackPointer
		rootWithHmac, ok := userlib.DatastoreGet(rootIndexKey)
		if !ok {
			err = errors.New("file not found")
			return nil, err
		}

		currentHMAC := rootWithHmac[:32]
		MarshaledRootBytes := rootWithHmac[32:]
		//currentRootHmac := createHMAC(FileInfoCFBKey, MarshaledRootBytes)
		currentRootHmac := createHMAC(BlockCFBKey, MarshaledRootBytes)

		if !userlib.Equal(currentRootHmac, currentHMAC) {
			err = errors.New("File block corrupted.")
			return nil, err
		}

		Root := &Root{}
		json.Unmarshal(MarshaledRootBytes, &Root)

		if offset < 0 || offset > StackPointer {
			err = errors.New("offset not in range")
			return nil, err
		}

		RequestedEncryptedBlock := Root.SIP2Block[offset]

		RequestedBlockDecrypted := make([]byte, len(RequestedEncryptedBlock))
		BlockIV := RequestedEncryptedBlock[:userlib.BlockSize]

		BlockCipherText := userlib.CFBDecrypter(BlockCFBKey, BlockIV)
		BlockCipherText.XORKeyStream(RequestedBlockDecrypted[userlib.BlockSize:], RequestedEncryptedBlock[userlib.BlockSize:])

		block := &Block{}
		json.Unmarshal(RequestedBlockDecrypted[userlib.BlockSize:], &block)

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

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	fileinfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		err = errors.New("File Not Found")
		return msgid, err
	} else {

		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		MarhshaledFileWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]

		fileHMAC := MarhshaledFileWithHMAC[:32]
		MarshaledFile := MarhshaledFileWithHMAC[32:]

		currentFileInfoHMAC := createHMAC(fileIndex, MarshaledFile)

		if !userlib.Equal(fileHMAC, currentFileInfoHMAC) {
			err = errors.New("File Information is tampered")
			return "", err
		}

		UnmarshaledFileInfo := &File{}
		json.Unmarshal(MarshaledFile, &UnmarshaledFileInfo)

		//rootIndexKey := UnmarshaledFileInfo.RootIndexUUID.String()
		//BlockCFBKey := UnmarshaledFileInfo.BlockCFBKey
		//StackPointer := UnmarshaledFileInfo.StackPointer

		SharingInfo := &sharingRecord{}
		SharingInfo.RootUUIDKey = UnmarshaledFileInfo.RootIndexUUID
		SharingInfo.BlockCFBKey = UnmarshaledFileInfo.BlockCFBKey
		SharingInfo.StackPointer = UnmarshaledFileInfo.StackPointer

		MarshaledSharingRecord, _ := json.Marshal(SharingInfo)

		recipientPublicKey, ok := userlib.KeystoreGet(recipient)
		//marshaledPublickey, _ := json.Marshal(recipientPublicKey)
		if !ok {
			err = errors.New("Public key of recipient not found")
			return "", err
		}

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

		MarshaledMessage, _ := json.Marshal(message)

		msgid = hex.EncodeToString(MarshaledMessage)

	}

	return msgid, err
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {

	messageID := &message{}
	message, _ := hex.DecodeString(msgid)

	json.Unmarshal(message, &messageID)

	EncryptedMessage := messageID.EncryptedMessage
	SignedMessage := messageID.Sign

	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		err = errors.New("Senders public key not found")
		return err
	}
	err = userlib.RSAVerify(&senderPublicKey, EncryptedMessage, SignedMessage)
	if err != nil {
		err = errors.New("Sign is not verified")
		return err
	}

	DecryptedMessage, err := userlib.RSADecrypt(&userdata.RSAPrivKey, EncryptedMessage, []byte("sharingTag"))
	if err != nil {
		err = errors.New("Decryption Failed")
		return err
	}

	sharedRecord := &sharingRecord{}
	json.Unmarshal(DecryptedMessage, &sharedRecord)

	FileInfo := &File{}
	FileInfo.RootIndexUUID = sharedRecord.RootUUIDKey
	FileInfo.BlockCFBKey = sharedRecord.BlockCFBKey
	FileInfo.StackPointer = sharedRecord.StackPointer
	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexHmacString := string(fileIndexHmac)

	marshaledFileInfo, _ := json.Marshal(FileInfo)
	fileInfoHMAC := createHMAC(fileIndex, marshaledFileInfo)

	marshaledFileInfoWithHMAC := make([]byte, 32+len(marshaledFileInfo))
	copy(marshaledFileInfoWithHMAC[:32], fileInfoHMAC)
	copy(marshaledFileInfoWithHMAC[32:], marshaledFileInfo)

	FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

	fileCipherText := make([]byte, userlib.BlockSize+len(marshaledFileInfoWithHMAC))
	fileiv := fileCipherText[:userlib.BlockSize]
	copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

	//Encrypting file info
	fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
	fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], marshaledFileInfoWithHMAC)

	userlib.DatastoreSet(fileIndexHmacString, fileCipherText)

	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	fileIndex := []byte(userdata.Username + filename)
	fileIndexHmac := userlib.NewHMAC(fileIndex).Sum(nil)
	fileIndexString := string(fileIndexHmac)

	fileInfoBlockEncrypted, ok := userlib.DatastoreGet(fileIndexString)
	if !ok {
		err = errors.New("file not found")
		return err
	} else {

		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)

		fileInfoBlockPlainText := make([]byte, len(fileInfoBlockEncrypted))
		fileIV := fileInfoBlockEncrypted[:userlib.BlockSize]

		fileCipher := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		fileCipher.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileInfoBlockEncrypted[userlib.BlockSize:])

		MarshaledFileInfoWithHMAC := fileInfoBlockPlainText[userlib.BlockSize:]
		previousFileHMAC := MarshaledFileInfoWithHMAC[:32]
		MarshaledFileInfo := MarshaledFileInfoWithHMAC[32:]

		currentHMAC := createHMAC(fileIndex, MarshaledFileInfo)

		if !userlib.Equal(currentHMAC, previousFileHMAC) {
			err = errors.New("You dont have access to view this file")
			return err
		}

		newBlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)
		newRootKeyUUID := bytesToUUID(userlib.RandomBytes(16))

		FileInfo := &File{}
		json.Unmarshal(MarshaledFileInfo, &FileInfo)

		oldBlockIndexKey := FileInfo.RootIndexUUID.String()
		//BlockCFBKey := FileInfo.BlockCFBKey
		//StackPointer := FileInfo.StackPointer

		DecrypteAndEncryptAgain(newRootKeyUUID, fileIndex, FileInfo.RootIndexUUID, FileInfo.BlockCFBKey, FileInfo.StackPointer, newBlockCFBKey)

		FileInfo.BlockCFBKey = newBlockCFBKey
		FileInfo.RootIndexUUID = newRootKeyUUID

		newlyMarshaledFileInfo, _ := json.Marshal(FileInfo)

		newFileHMAC := createHMAC(fileIndex, newlyMarshaledFileInfo)

		newFileWithHMAC := make([]byte, 32+len(newlyMarshaledFileInfo))
		copy(newFileWithHMAC[:32], newFileHMAC)
		copy(newFileWithHMAC[32:], newlyMarshaledFileInfo)

		fileCipherText := make([]byte, userlib.BlockSize+len(newFileWithHMAC))
		copy(fileCipherText[:userlib.BlockSize], fileIV)
		fileCipherT := userlib.CFBEncrypter(FileInfoCFBKey, fileIV)
		fileCipherT.XORKeyStream(fileCipherText[userlib.BlockSize:], newFileWithHMAC)

		userlib.DatastoreSet(fileIndexString, fileCipherText)

		userlib.DatastoreDelete(oldBlockIndexKey)

	}

	return err
}

func DecrypteAndEncryptAgain(newRootKeyUUID uuid.UUID, fileIndex []byte, RootIndexUUID uuid.UUID, oldBlockCFBKey []byte, StackPointer int, newBlockCFBKey []byte) (err error) {

	MarshaledRootWithHmac, ok := userlib.DatastoreGet(RootIndexUUID.String())
	if !ok {
		err = errors.New("Root not found")
		return err
	} else {

		RootPreviousHmac := MarshaledRootWithHmac[:32]
		RootData := MarshaledRootWithHmac[32:]
		CurrentRootHmac := createHMAC(oldBlockCFBKey, RootData)

		if !userlib.Equal(RootPreviousHmac, CurrentRootHmac) {
			err = errors.New("Block is corrupted")
			return err
		}

		root := &Root{}
		json.Unmarshal(RootData, &root)

		ExistingBlocksInFile := StackPointer + 1

		for i := 0; i < ExistingBlocksInFile; i++ {
			if root.SIP2Block[i] != nil {

				BlockToDecrypt := root.SIP2Block[i]
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

				marshaledBlockWithNewHMAC, _ := json.Marshal(tempBlock)

				EncryptedBlock := make([]byte, userlib.BlockSize+len(marshaledBlockWithNewHMAC))
				newBlockIV := EncryptedBlock[:userlib.BlockSize]
				copy(newBlockIV, userlib.RandomBytes(userlib.BlockSize))

				BlockCipherT := userlib.CFBEncrypter(newBlockCFBKey, newBlockIV)
				BlockCipherT.XORKeyStream(EncryptedBlock[userlib.BlockSize:], marshaledBlockWithNewHMAC)

				root.SIP2Block[i] = EncryptedBlock

			}
		}

		newlyMarshaledRoot, _ := json.Marshal(root)

		newlyMarshaledRootHMAC := createHMAC(newBlockCFBKey, newlyMarshaledRoot)
		newMarshaledRootWithHMAC := make([]byte, 32+len(newlyMarshaledRoot))
		copy(newMarshaledRootWithHMAC[:32], newlyMarshaledRootHMAC)
		copy(newMarshaledRootWithHMAC[32:], newlyMarshaledRoot)

		RootIndexKey := newRootKeyUUID.String()
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

		uspass := []byte(username + password)
		userHMAC := userlib.NewHMAC([]byte(uspass))
		HMACKeyString := string(userHMAC.Sum(nil))

		_, ok := userlib.DatastoreGet(HMACKeyString)
		if ok {
			err = errors.New("User cannot be initilized again.")
			return nil, err
		}

		argonKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
		RSAPrivKey, _ := userlib.GenerateRSAKey()

		userdataptr = &User{}
		userdataptr.Username = username
		userdataptr.Password = password
		userdataptr.RSAPrivKey = *RSAPrivKey

		//Convert userdata to bytes
		marshaledData, _ := json.Marshal(userdataptr)

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
