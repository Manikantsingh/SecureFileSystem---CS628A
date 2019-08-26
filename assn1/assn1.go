package main

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"bytes"
	"crypto/rsa"
	"hash"

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

	// fileError := fetchedDetails.StoreFile("filename", []byte("content of the file"))
	// if fileError != nil {
	// 	println("**** Unable to store file ****", fileError.Error())
	// }

	data1 := userlib.RandomBytes(4096)
	fileError := fetchedDetails.StoreFile("filename1", data1)
	if fileError != nil {
		println("**** Unable to store file ****", fileError.Error())
	}

	data2, _ := fetchedDetails.LoadFile("filename1", 0)

	if !bytes.Equal(data1, data2) {
		//println("data corrupted", blockerror.Error())
	} else {
		println("data is not corrupted")
	}
	// setDetails.LoadFile("filename1")

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
	RSAPrivKey *rsa.PrivateKey
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
	Hmac hash.Hash
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

		// FileIndex := []byte(userdata.Username + filename)
		// HmacFileIndex := userlib.NewHMAC(FileIndex)
		// HmacFileIndexString := string(HmacFileIndex.Sum(nil))

		// retrievedFile := &File{}
		fileInfoBlock := &File{}
		root := &Root{}

		fileInfoBlock.RootIndexUUID = rootKeyUUID

		blocksInFile := len(data) / configBlockSize

		//Setting the actual data in the block with its calculated hmac
		//************ Starting block encryption ************
		block := &Block{}
		block.Data = data[:configBlockSize]
		block.Hmac = userlib.NewHMAC(block.Data)
		MarshaledBlockData, _ := json.Marshal(block)

		println("Length of Marshaled data: ", len(MarshaledBlockData))

		//Generate Block CFB encryption and decryption key.
		BlockCFBKey := userlib.Argon2Key(fileIndex, userlib.RandomBytes(32), 32)

		//Encrypt file with above generated Block CFB
		blockCipherText := make([]byte, userlib.BlockSize+len(MarshaledBlockData))
		iv := blockCipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))
		println("IV : ", hex.EncodeToString(iv), " block CFB KEY: ", hex.EncodeToString(BlockCFBKey))

		blockCipher := userlib.CFBEncrypter(BlockCFBKey, iv)
		blockCipher.XORKeyStream(blockCipherText[userlib.BlockSize:], MarshaledBlockData)
		// ********* Block Encryption done ************

		//println("marshaled block:", hex.EncodeToString(blockCipherText[userlib.BlockSize:]))

		currentBlockIndex := 0
		currentBytePosition := configBlockSize
		root.SIP2Block[currentBlockIndex] = blockCipherText
		currentBlockIndex += 1

		for i := 1; i < blocksInFile; i++ {
			println("Entred In the loop ceate blocks and store")
			currentBlock := &Block{}
			currentBlock.Data = data[currentBytePosition : currentBytePosition+configBlockSize]
			currentBlock.Hmac = userlib.NewHMAC(currentBlock.Data)

			MarshaledBlock, _ := json.Marshal(currentBlock)

			currentBlockCipher := make([]byte, userlib.BlockSize+len(MarshaledBlock))
			currentBlockIV := blockCipherText[:userlib.BlockSize]
			copy(currentBlockIV, userlib.RandomBytes(userlib.BlockSize))
			blockCipherIntermediate := userlib.CFBEncrypter(BlockCFBKey, currentBlockIV)
			blockCipherIntermediate.XORKeyStream(currentBlockCipher[userlib.BlockSize:], MarshaledBlock)

			root.SIP2Block[currentBlockIndex] = currentBlockCipher

			currentBlockIndex += 1
			currentBytePosition += configBlockSize
		}

		MarshaledRoot, _ := json.Marshal(root)

		rootHMAC := userlib.NewHMAC(MarshaledRoot)
		rootHMacByte := rootHMAC.Sum(nil)
		//println("Hmac Length : ", len(rootHMacByte))

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
		fileInfoBlock.StackPointer = len(data)/configBlockSize - 1

		MarhsaledFile, _ := json.Marshal(fileInfoBlock)

		fileCipherText := make([]byte, userlib.BlockSize+len(MarhsaledFile))
		fileiv := fileCipherText[:userlib.BlockSize]
		copy(fileiv, userlib.RandomBytes(userlib.BlockSize))

		//Encrypting file info
		fileCipher := userlib.CFBEncrypter(FileInfoCFBKey, fileiv)
		fileCipher.XORKeyStream(fileCipherText[userlib.BlockSize:], MarhsaledFile)

		userlib.DatastoreSet(fileIndexHmacString, fileCipherText)

	}
	return err
}

// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return err
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

		//Generate Fileinfo CFB key
		FileInfoCFBKey := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
		println("File Info CFB Key: ", userdata.Username, filename, hex.EncodeToString(FileInfoCFBKey))

		fileInfoBlockPlainText := make([]byte, len(fileinfoBlockEncrypted))
		fileIV := fileinfoBlockEncrypted[:userlib.BlockSize]
		cipherText := userlib.CFBDecrypter(FileInfoCFBKey, fileIV)
		cipherText.XORKeyStream(fileInfoBlockPlainText[userlib.BlockSize:], fileinfoBlockEncrypted[userlib.BlockSize:])

		fileInfo := fileInfoBlockPlainText[userlib.BlockSize:]

		UnmarshaledFileInfo := &File{}
		json.Unmarshal(fileInfo, &UnmarshaledFileInfo)

		rootIndexKey := UnmarshaledFileInfo.RootIndexUUID
		println("Fetching files from", rootIndexKey.String())
		rootWithHmac, ok := userlib.DatastoreGet(rootIndexKey.String())
		if !ok {
			err = errors.New("file not found")
		}

		MarshaledRootByteHmac := rootWithHmac[:len(fileIndexHmac)]
		MarshaledRootBytes := rootWithHmac[len(fileIndexHmac):]

		currentRootHmac := userlib.NewHMAC(MarshaledRootBytes).Sum(nil)

		println(" Both hmac: ", hex.EncodeToString(MarshaledRootByteHmac), " ", hex.EncodeToString(currentRootHmac))

		if !bytes.Equal(currentRootHmac, MarshaledRootByteHmac) {
			err = errors.New("File block corrupted.")
		}

		Root := &Root{}
		json.Unmarshal(MarshaledRootBytes, &Root)

		requestedBlock := Root.SIP2Block[offset]

		//Decrypting Block
		MarshaledBlockPlainText := make([]byte, len(requestedBlock))
		blockIV := requestedBlock[:userlib.BlockSize]
		println("BlockIV : ", hex.EncodeToString(blockIV), " block CFB KEY: ", hex.EncodeToString(UnmarshaledFileInfo.BlockCFBKey))

		cipherTextBlock := userlib.CFBDecrypter(UnmarshaledFileInfo.BlockCFBKey, blockIV)
		cipherTextBlock.XORKeyStream(MarshaledBlockPlainText[userlib.BlockSize:], requestedBlock[userlib.BlockSize:])

		//println("marshaled block 2:", hex.EncodeToString(MarshaledBlockPlainText[userlib.BlockSize:]))
		ActualBlock := &Block{}
		json.Unmarshal(MarshaledBlockPlainText[userlib.BlockSize:], &ActualBlock)

		BlockActualData := ActualBlock.Data

		BlockActualHmac := ActualBlock.Hmac

		CurrentBlockHmac := userlib.NewHMAC(BlockActualData).Sum(nil)
		println(" Both hmac: ", hex.EncodeToString(CurrentBlockHmac), " ", hex.EncodeToString(BlockActualHmac))
		// if bytes.Equal(CurrentBlockHmac, BlockActualHmac) {
		// 	println("Block HMAC also matched")
		// } else {
		// 	err = errors.New("File is corrupted")
		// }

		// if !bytes.Equal(rootHmacFetched, currentRootHmac) {
		// 	err = errors.New("File block corrupted.")
		// } else {
		// 	ActualBlock := &Block{}

		// 	json.Unmarshal(MarshaledPlainText[userlib.BlockSize:], &ActualBlock)
		// 	BlockFetchedEncryptedBytes := ActualBlock.SIP2Block[offset]

		// 	json.Unmarshal(blockDataPlainText[userlib.BlockSize:], &ActualBlock)

		// 	BlockActualData := ActualBlock.Data
		// 	BlockActualHmac := ActualBlock.Hmac.Sum(nil)

		// 	CurrentHmac := userlib.NewHMAC(BlockActualData).Sum(nil)

		// 	if bytes.Equal(CurrentHmac, BlockActualHmac) {
		// 		data = BlockActualData
		// 	} else {
		// 		err = errors.New("File is corrupted")
		// 	}

		// }

	}

	return data, err
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	return msgid, err
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	return err
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

		println("Userkey HMAC length: ", len(HMACKey))

		returnedbytes, _ := userlib.DatastoreGet("testkey")
		println("len : ", len(returnedbytes))

		//blockCFBKey := userlib.Argon2Key(uspass, userlib.RandomBytes(32), 32)
		//fileInfoCFBKey := userlib.Argon2Key(uspass, userlib.RandomBytes(32), 32)

		RSAPrivKey, _ := userlib.GenerateRSAKey()

		userdataptr = &User{}
		userdataptr.Username = username
		userdataptr.Password = password
		userdataptr.RSAPrivKey = RSAPrivKey
		//userdataptr.BlockCFBKey = blockCFBKey
		//userdataptr.FileInfoCFBKey = fileInfoCFBKey

		//Convert userdata to bytes
		marshaledData, _ := json.Marshal(userdataptr)

		//Initailize empty cipherText and IV
		cipherText := make([]byte, userlib.BlockSize+len(marshaledData))
		iv := cipherText[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))

		//Encrypting plaintext using HMACKey and iv
		cipher := userlib.CFBEncrypter(HMACKey, iv)
		cipher.XORKeyStream(cipherText[userlib.BlockSize:], marshaledData)

		//Decrypting cipherText to plain text
		// deCipher := userlib.CFBDecrypter(HMACKey, iv)
		// deCipher.XORKeyStream(cipherText[userlib.BlockSize:], cipherText[userlib.BlockSize:])

		//Umarshalling the text to user struct
		// var a User
		// json.Unmarshal(cipherText[userlib.BlockSize:], &a)
		// println(a.Password)

		//Stored user data in datastore in CFB encrypted form
		//println("userHMACString:", HMACKeyString)

		userlib.DatastoreSet(HMACKeyString, cipherText)
		userlib.KeystoreSet(username, RSAPrivKey.PublicKey)

		// cipherText := make([]byte, userlib.BlockSize+len(jd))
		// iv := cipherText[:userlib.BlockSize]
		// copy(iv, userlib.RandomBytes(userlib.BlockSize))

		// cipher := userlib.CFBEncrypter(HMACByteKey, iv)
		// cipher.XORKeyStream(cipherText[userlib.BlockSize:], jd)

		// //println("usdf", hex.EncodeToString(cipherText))

		// decryptStream := userlib.CFBDecrypter(HMACByteKey, iv)
		// decryptStream.XORKeyStream(cipherText[userlib.BlockSize:], cipherText[userlib.BlockSize:])
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
	userHMAC := userlib.NewHMAC([]byte(uspass))
	HMACKeyString := string(userHMAC.Sum(nil))
	HMACKey := userHMAC.Sum(nil)

	encryptedText, ok := userlib.DatastoreGet(HMACKeyString)
	if !ok {
		err = errors.New("User does not exists")
	} else {

		plainText := make([]byte, len(encryptedText))
		iv := encryptedText[:userlib.BlockSize]
		cipherText := userlib.CFBDecrypter(HMACKey, iv)
		cipherText.XORKeyStream(plainText[userlib.BlockSize:], encryptedText[userlib.BlockSize:])

		json.Unmarshal(plainText[userlib.BlockSize:], &userdataptr)

	}
	return userdataptr, err
}
