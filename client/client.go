package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// globals
var FileContentLength int = 240

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string               //To Remove, not right now since some current tests rely on it
	FilesToUUID   map[string]uuid.UUID //Maps filenames to storage keys
	FilesToSender map[string]string
	RSAPrivateKey userlib.PKEDecKey //RSA private key
	DSSignKey     userlib.DSSignKey
	Password      string
}

type FileMain struct {
	FirstFilePart uuid.UUID
	LastFilePart  uuid.UUID
}

// sizeof(FilePart)==256 bytes
type FilePart struct {
	NextFilePart uuid.UUID //16 bytes
	Content      []byte    //FileContentLength bytes max
}

type Invitation struct {
	NodeSymKey []byte
	NodeUUID   uuid.UUID
}

type Node struct {
	ChildsSymKeys map[string][]byte
	ChildsUUIDs   map[string]uuid.UUID
	FileSymKey    []byte
	FileUUID      uuid.UUID
}

type StructWrapper struct {
	EncryptedStruct []byte
	HMACOrSign      []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}
	//Calculate Salt for SymKey
	salt := userlib.Hash([]byte(username))[0:16]
	//Calculate the symmetric key to encrypt the User Struct and User UUID (position of EncryptedUserStructAndHMAC Struct in DataStore)
	SymK := userlib.Argon2Key([]byte(password), salt, 16)
	UserUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[0:16])
	if err != nil {
		return nil, err
	}
	//Calculate RSA public and private keys
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	//Store the RSA Public Key in KeyStore
	err = userlib.KeystoreSet(username, PKEEncKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"DSVerifyKey", DSVerifyKey)
	if err != nil {
		return nil, err
	}
	//Initialize User Struct
	UserStruct := &User{
		Username:      username,
		RSAPrivateKey: PKEDecKey,
		FilesToUUID:   make(map[string]uuid.UUID),
		DSSignKey:     DSSignKey,
		Password:      password,
		FilesToSender: make(map[string]string),
	}
	userBytes, err := json.Marshal(UserStruct)
	if err != nil {
		return nil, err
	}
	//Encrypt User Struct and calculate HMAC on cipher
	encryptedUserStruct := userlib.SymEnc(SymK, userlib.RandomBytes(16), userBytes)
	sum, err := userlib.HMACEval(SymK, encryptedUserStruct)
	if err != nil {
		return nil, err
	}
	//Initialize EncryptedUserStructAndHMAC Struct
	EncryptedUserStructAndHMACStruct := &StructWrapper{
		EncryptedStruct: encryptedUserStruct,
		HMACOrSign:      sum,
	}

	encryptedUserStructAndHMACBytes, err := json.Marshal(EncryptedUserStructAndHMACStruct)
	if err != nil {
		return nil, err
	}
	//Store EncryptedUserStructAndHMAC Struct in DataStore at UserUUID
	userlib.DatastoreSet(UserUUID, encryptedUserStructAndHMACBytes)
	return UserStruct, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//Calculate userUUID (position of EncryptedUserStructAndHMAC Struct in DataStore) and salt for SymKey
	userUUID, err1 := uuid.FromBytes(userlib.Hash([]byte(username))[0:16])
	salt := userlib.Hash([]byte(username))[0:16]
	if err1 != nil {
		return
	}
	//Get the encryptedUserStructAndHMACBytes in DataStore at UserUUID
	encryptedUserStructAndHMACBytes, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return
	}

	var EncryptedUserStructAndHMACStruct StructWrapper

	err = json.Unmarshal(encryptedUserStructAndHMACBytes, &EncryptedUserStructAndHMACStruct)
	if err != nil {
		return
	}
	//Calculate symK to decrypt the User Struct
	symK := userlib.Argon2Key([]byte(password), salt, 16)
	//Get the HMAC and User Struct in EncryptedUserStructAndHMAC Struct
	retrievedHMAC := EncryptedUserStructAndHMACStruct.HMACOrSign
	retrievedEncryptedUserStruct := EncryptedUserStructAndHMACStruct.EncryptedStruct
	//Calculate HMAC of encrypted User Struct
	HMAC, err := userlib.HMACEval(symK, retrievedEncryptedUserStruct)
	if err != nil {
		return nil, err
	}
	if userlib.HMACEqual(retrievedHMAC, HMAC) {
		var UserStruct User
		//Decrypt the User Struct
		userStructBytes := userlib.SymDec(symK, retrievedEncryptedUserStruct)
		err = json.Unmarshal(userStructBytes, &UserStruct)
		if err != nil {
			return nil, err
		}
		return &UserStruct, nil
	} else {
		return
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//we actualize userdata
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//Algorithm of this function has been designed for simplcity not efficiency X)

	/*

		1. We split the content into 240 bytes parts and store them. (encrypted)

	*/
	//Storing
	fileSymKey := userlib.RandomBytes(16)
	filePartsUUIDs, err := FileContentToFilePartsUUIDs(content, fileSymKey)
	if err != nil {
		return err
	}

	//Now we store the FileMain
	FileMain := FileMain{
		FirstFilePart: filePartsUUIDs[0],
		LastFilePart:  filePartsUUIDs[len(filePartsUUIDs)-1],
	}
	FileMainBytes, err := json.Marshal(FileMain)
	if err != nil {
		return err
	}

	fileMainUUID := uuid.New()
	err = StoreDataWithSymEncryption(fileMainUUID, fileSymKey, FileMainBytes)
	if err != nil {
		return err
	}

	/*

		We now create the root node of the file system.

	*/

	//We create the root
	Root := Node{
		FileUUID:      fileMainUUID,
		FileSymKey:    fileSymKey,
		ChildsSymKeys: make(map[string][]byte),
		ChildsUUIDs:   make(map[string]userlib.UUID),
	}

	rootUUID := uuid.New()
	rootBytes, err := json.Marshal(Root)
	if err != nil {
		return err
	}

	rootSymKey := userlib.RandomBytes(16)

	err = StoreDataWithSymEncryption(rootUUID, rootSymKey, rootBytes)
	if err != nil {
		return err
	}

	//Creating own invitation
	invitationUUID := uuid.New()
	invitation := Invitation{
		NodeSymKey: rootSymKey,
		NodeUUID:   rootUUID,
	}

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return err
	}

	//fetching Public Signing key

	publicCryptKey, ok := userlib.KeystoreGet(userdata.Username)

	if !ok {
		return errors.New("coudln't find PublicCryptKey of user")
	}

	//Crypting invitation with PublicKey
	err = StoreDataWithAsyEncryption(invitationUUID, userdata.DSSignKey, publicCryptKey, invitationBytes)
	if err != nil {
		return err
	}

	userdata.FilesToUUID[filename] = invitationUUID
	userdata.FilesToSender[filename] = userdata.Username

	err = UpdateUserObject(userdata)
	if err != nil {
		return errors.New("coudln't update userData of user")
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//we actualize userdata
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	senderUsername, ok := userdata.FilesToSender[filename]
	if !ok {
		return errors.New("coudln't find senderUsername of file")
	}

	invitationPtr, err := GetInvitationOfUser(userdata, filename, senderUsername)
	if err != nil {
		return err
	}

	// Fetch the node
	nodeBytes, err := FetchAndDecryptHMAC(invitationPtr.NodeUUID, invitationPtr.NodeSymKey)
	if err != nil {
		return err
	}

	var Node Node
	err = json.Unmarshal(nodeBytes, &Node)
	if err != nil {
		return err
	}

	//Fetch FileMain
	fileMainBytes, err := FetchAndDecryptHMAC(Node.FileUUID, Node.FileSymKey)
	if err != nil {
		return err
	}

	var FileMain FileMain
	err = json.Unmarshal(fileMainBytes, &FileMain)
	if err != nil {
		return err
	}

	// Fetch last FilePart
	lastFilePartUUID := FileMain.LastFilePart

	for len(content) > 0 {
		// Create a new FilePart for this chunk of content
		var tmpData []byte
		for i := 0; i < FileContentLength && len(content) > 0; i++ {
			tmpData = append(tmpData, content[0])
			content = content[1:]
		}

		newFilePart := FilePart{
			NextFilePart: uuid.Nil,
			Content:      tmpData,
		}

		// Encrypt and store the new FilePart
		newFilePartBytes, err := json.Marshal(newFilePart)
		if err != nil {
			return err
		}

		newFilePartUUID := uuid.New()
		err = StoreDataWithSymEncryption(newFilePartUUID, Node.FileSymKey, newFilePartBytes)
		if err != nil {
			return err
		}

		// Update the NextFilePart field of the previous lastFilePart to point to the new FilePart
		lastFilePartBytes, err := FetchAndDecryptHMAC(lastFilePartUUID, Node.FileSymKey)
		if err != nil {
			return err
		}

		var lastFilePart FilePart
		err = json.Unmarshal(lastFilePartBytes, &lastFilePart)
		if err != nil {
			return err
		}

		lastFilePart.NextFilePart = newFilePartUUID

		// Update the lastFilePart in the data store
		lastFilePartBytes, err = json.Marshal(lastFilePart)
		if err != nil {
			return err
		}

		err = StoreDataWithSymEncryption(lastFilePartUUID, Node.FileSymKey, lastFilePartBytes)
		if err != nil {
			return err
		}

		// Update the fileMain to point to the new lastFilePart
		FileMain.LastFilePart = newFilePartUUID
	}

	// Update the node and FileMain in the data store
	nodeBytes, err = json.Marshal(Node)
	if err != nil {
		return err
	}

	err = StoreDataWithSymEncryption(invitationPtr.NodeUUID, invitationPtr.NodeSymKey, nodeBytes)
	if err != nil {
		return err
	}

	// Update the FileMain in the data store
	fileMainBytes, err = json.Marshal(FileMain)
	if err != nil {
		return err
	}

	err = StoreDataWithSymEncryption(Node.FileUUID, Node.FileSymKey, fileMainBytes)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//we actualize userdata
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}

	//We get the invitation
	senderUsername, ok := userdata.FilesToSender[filename]

	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	invitationPtr, err := GetInvitationOfUser(userdata, filename, senderUsername)
	if err != nil {
		return nil, err
	}

	//We get the corresponding node
	nodeBytes, err := FetchAndDecryptHMAC(invitationPtr.NodeUUID, invitationPtr.NodeSymKey)
	if err != nil {
		return nil, err
	}

	var Node Node
	err = json.Unmarshal(nodeBytes, &Node)
	if err != nil {
		return nil, err
	}

	//fetching FileMain
	fileMainBytes, err := FetchAndDecryptHMAC(Node.FileUUID, Node.FileSymKey)
	if err != nil {
		return nil, err
	}

	var FileMain FileMain
	err = json.Unmarshal(fileMainBytes, &FileMain)
	if err != nil {
		return nil, err
	}

	//Fetching actual data
	var buff []byte

	//artificial first part for the loop to work
	CurrentPart := FilePart{
		NextFilePart: FileMain.FirstFilePart,
		Content:      nil,
	}

	for CurrentPart.NextFilePart != uuid.Nil {
		filePartBytes, err := FetchAndDecryptHMAC(CurrentPart.NextFilePart, Node.FileSymKey)
		if err != nil {
			return nil, err
		}

		var FilePart FilePart

		err = json.Unmarshal(filePartBytes, &FilePart)
		if err != nil {
			return nil, err
		}

		buff = append(buff, FilePart.Content...)
		CurrentPart = FilePart
	}

	return buff, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//we actualize userdata
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}

	//Get the invitation of the User
	senderusername, ok := userdata.FilesToSender[filename]
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("file not found"))
	}
	invitationUserPtr, err := GetInvitationOfUser(userdata, filename, senderusername)
	if err != nil {
		return uuid.Nil, err
	}

	//Get the Node of the User
	nodeUser, err := GetNodeOfUserFromInvitation(*invitationUserPtr)
	if err != nil {
		return uuid.Nil, err
	}

	var NodeUserStruct Node
	err = json.Unmarshal(nodeUser, &NodeUserStruct)
	if err != nil {
		return uuid.Nil, err
	}

	//Initialize the Node for the shared User
	NodeSharedUserStruct := &Node{
		FileSymKey:    NodeUserStruct.FileSymKey,
		FileUUID:      NodeUserStruct.FileUUID,
		ChildsSymKeys: make(map[string][]byte),
		ChildsUUIDs:   make(map[string]userlib.UUID),
	}
	//Calculate the nodeSymKey for the Node of the Shared User
	nodeSymKey := userlib.RandomBytes(16)
	nodeSharedUserBytes, err := json.Marshal(NodeSharedUserStruct)
	if err != nil {
		return uuid.Nil, err
	}
	//Calculate nodeUUID (position of NodeSharedUserStruct in the DataStore)
	nodeUUID := uuid.New()
	//Encrypt the NodeSharedUserStruct with NodeSymKey and store this in the DataStore at NodeUUID

	err = StoreDataWithSymEncryption(nodeUUID, nodeSymKey, nodeSharedUserBytes)
	if err != nil {
		return uuid.Nil, err
	}
	//Initialize the Invitation Struct for the Shared User
	invitationSharedUserStruct := &Invitation{
		NodeSymKey: nodeSymKey,
		NodeUUID:   nodeUUID,
	}
	//Get the RSA public key of the Shared User
	RSAPublicKeySharedUser, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipient not found"))
	}
	invitationSharedUserBytes, err := json.Marshal(invitationSharedUserStruct)
	if err != nil {
		return uuid.Nil, err
	}
	invitationSharedUserUUID := uuid.New()

	//Store the encrypted Invitation of the Shared User in the DataStore at invitationSharedUserUUID (random UUID)
	err = StoreDataWithAsyEncryption(invitationSharedUserUUID, userdata.DSSignKey, RSAPublicKeySharedUser, invitationSharedUserBytes)
	if err != nil {
		return uuid.Nil, err
	}

	//Update the Node Struct of the User
	NodeUserStruct.ChildsSymKeys[recipientUsername] = nodeSymKey
	NodeUserStruct.ChildsUUIDs[recipientUsername] = nodeUUID

	NodeUserBytes, err := json.Marshal(NodeUserStruct)
	if err != nil {
		return uuid.Nil, err
	}
	err = StoreDataWithSymEncryption(invitationUserPtr.NodeUUID, invitationUserPtr.NodeSymKey, NodeUserBytes)
	if err != nil {
		return uuid.Nil, err
	}

	return invitationSharedUserUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//we actualize userdata
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	_, ok := userdata.FilesToUUID[filename]
	if ok {
		return errors.New("the user already has a file with the chosen filename in their personal file namespace")
	}
	userdata.FilesToUUID[filename] = invitationPtr
	userdata.FilesToSender[filename] = senderUsername

	err = UpdateUserObject(userdata)
	if err != nil {
		return err
	}

	_, err = userdata.LoadFile(filename)
	if err != nil {
		return errors.New("coudn't load the file")
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//we actualize userdata
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("error in GetUser")
	}

	//Get Invitation of Owner
	invitationOwnerStructPtr, err := GetInvitationOfUser(userdata, filename, userdata.Username)
	if err != nil {
		return errors.New("error in GetInvitationOfUser")
	}

	//Get Node of Owner
	nodeOwner, err := GetNodeOfUserFromInvitation(*invitationOwnerStructPtr)
	if err != nil {
		return errors.New("error in GetNodeOfUserFromInvitation")
	}

	var nodeOwnerStruct Node
	err = json.Unmarshal(nodeOwner, &nodeOwnerStruct)
	if err != nil {
		return err
	}
	//Get the UUID and the SymKey of the Node of the revoked user
	nodeUUIDRevokedUser, ok := nodeOwnerStruct.ChildsUUIDs[recipientUsername]
	if !ok {
		return errors.New("couldn't fetch childsuui at recipientusername")
	}
	symKeyRevokedUser, ok := nodeOwnerStruct.ChildsSymKeys[recipientUsername]
	if !ok {
		return errors.New("couldn't fetch ChildsSymKeys at recipientUsername")
	}

	err = RemoveAllChildsOfNode(nodeUUIDRevokedUser, symKeyRevokedUser)
	if err != nil {
		return errors.New("error in RemoveAllChildsOfNode")
	}
	delete(nodeOwnerStruct.ChildsSymKeys, recipientUsername)
	delete(nodeOwnerStruct.ChildsUUIDs, recipientUsername)

	nodeUserBytes, err := json.Marshal(nodeOwnerStruct)
	if err != nil {
		return err
	}
	StoreDataWithSymEncryption(invitationOwnerStructPtr.NodeUUID, invitationOwnerStructPtr.NodeSymKey, nodeUserBytes)

	//Generate a new SymKey and UUID for the file
	newSymKeyFile := userlib.RandomBytes(16)
	newUUIDFile := uuid.New()

	//Get the file, decrypts it with the old SymKey, encrypts it with newSymKeyFile (random key) and stores the file in the DataStore at newUUIDFile (random UUID)

	//get FileMainStruct
	mainFileBytes, err := FetchAndDecryptHMAC(nodeOwnerStruct.FileUUID, nodeOwnerStruct.FileSymKey)
	if err != nil {
		return err
	}
	var MainFileStruct FileMain
	err = json.Unmarshal(mainFileBytes, &MainFileStruct)
	if err != nil {
		return err
	}

	//get FileContent
	fileContent, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	partsUUID, err := FileContentToFilePartsUUIDs(fileContent, newSymKeyFile)
	if err != nil {
		return err
	}

	//delete the old file
	err = DeleteFilesPartFromFileMain(nodeOwnerStruct.FileUUID, nodeOwnerStruct.FileSymKey)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(nodeOwnerStruct.FileUUID)

	MainFileStruct.FirstFilePart = partsUUID[0]
	MainFileStruct.LastFilePart = partsUUID[len(partsUUID)-1]

	NewMainFilesBytes, err := json.Marshal(MainFileStruct)
	if err != nil {
		return err
	}
	//decryptedFileBytes := userlib.SymDec(NodeUserStruct.FileSymKey, encryptedFileBytes)

	err = StoreDataWithSymEncryption(newUUIDFile, newSymKeyFile, NewMainFilesBytes)

	if err != nil {
		return err
	}
	//Delete the file at the old UUID
	userlib.DatastoreDelete(nodeOwnerStruct.FileUUID)

	err = UpdateValueForEachNode(invitationOwnerStructPtr.NodeUUID, invitationOwnerStructPtr.NodeSymKey, newSymKeyFile, newUUIDFile)
	if err != nil {
		return err
	}
	return nil
}

/*

	Helper functions

*/

func FetchAndDecryptHMAC(UUID userlib.UUID, SymKey []byte) (DecryptedStructBytes []byte, err error) {
	StructWrapper := StructWrapper{}

	StructWrapperBytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New("couldn't fetch StructWrapperBytes")
	}

	err = json.Unmarshal(StructWrapperBytes, &StructWrapper)
	if err != nil {
		return nil, errors.New("couldn't unmarshal StructWrapperBytes")
	}
	calulatedHMAC, err := userlib.HMACEval(SymKey, StructWrapper.EncryptedStruct)
	if err != nil {
		return nil, errors.New("couldn't calculate HMAC")
	}
	if userlib.HMACEqual(calulatedHMAC, StructWrapper.HMACOrSign) {
		return userlib.SymDec(SymKey, StructWrapper.EncryptedStruct), nil
	}
	return nil, errors.New("HMACs are not equal")
}
func FetchAndDecryptSign(UUID userlib.UUID, PKEDecKey userlib.PKEDecKey, senderUsername string) (DecryptedStructBytes []byte, err error) {
	StructWrapper := StructWrapper{}

	StructWrapperBytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New("couldn't fetch StructWrapperBytes")
	}

	err = json.Unmarshal(StructWrapperBytes, &StructWrapper)
	if err != nil {
		return nil, errors.New("couldn't unmarshal StructWrapperBytes")
	}

	DSVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DSVerifyKey")
	if !ok {
		return
	}
	err2 := userlib.DSVerify(DSVerifyKey, StructWrapper.EncryptedStruct, StructWrapper.HMACOrSign)
	if err2 == nil {
		decryptedStructBytes, err4 := userlib.PKEDec(PKEDecKey, StructWrapper.EncryptedStruct)
		if err4 != nil {
			return
		}
		return decryptedStructBytes, nil
	}
	return
}

func StoreDataWithSymEncryption(UUID userlib.UUID, SymKey []byte, data []byte) (err error) {

	encryptedData := userlib.SymEnc(SymKey, userlib.RandomBytes(16), data)
	HMAC, err1 := userlib.HMACEval(SymKey, encryptedData)
	if err1 != nil {
		return
	}
	StructWrapper := &StructWrapper{

		EncryptedStruct: encryptedData,
		HMACOrSign:      HMAC,
	}
	StructWrapperBytes, err2 := json.Marshal(StructWrapper)
	if err2 != nil {
		return
	}
	userlib.DatastoreSet(UUID, StructWrapperBytes)
	return nil
}

func StoreDataWithAsyEncryption(UUID userlib.UUID, DSSignKey userlib.DSSignKey, PKEEncKey userlib.PKEEncKey, data []byte) (err error) {

	encryptedData, err4 := userlib.PKEEnc(PKEEncKey, data)
	if err4 != nil {
		return err4
	}
	sign, err1 := userlib.DSSign(DSSignKey, encryptedData)
	if err1 != nil {
		return err1
	}
	StructWrapper := &StructWrapper{

		EncryptedStruct: encryptedData,
		HMACOrSign:      sign,
	}
	StructWrapperBytes, err2 := json.Marshal(StructWrapper)
	if err2 != nil {
		return err2
	}
	userlib.DatastoreSet(UUID, StructWrapperBytes)
	return nil
}

func UpdateUserObject(userdata *User) (err error) {
	//Calculate Salt for SymKey
	salt := userlib.Hash([]byte(userdata.Username))[0:16]
	//Calculate the symmetric key to encrypt the User Struct and User UUID (position of EncryptedUserStructAndHMAC Struct in DataStore)
	SymK := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	UserUUID, err1 := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
	if err1 != nil {
		return err1
	}
	UserBytes, err4 := json.Marshal(&userdata)
	if err4 != nil {
		return err4
	}
	//Encrypt User Struct and calculate HMAC on cipher
	EncryptedUserStruct := userlib.SymEnc(SymK, userlib.RandomBytes(16), UserBytes)
	sum, err5 := userlib.HMACEval(SymK, EncryptedUserStruct)
	if err5 != nil {
		return err5
	}
	//Initialize EncryptedUserStructAndHMAC Struct
	EncryptedUserStructAndHMACStruct := &StructWrapper{
		EncryptedStruct: EncryptedUserStruct,
		HMACOrSign:      sum,
	}

	EncryptedUserStructAndHMACBytes, err6 := json.Marshal(EncryptedUserStructAndHMACStruct)
	if err6 != nil {
		return err6
	}
	//Store EncryptedUserStructAndHMAC Struct in DataStore at UserUUID
	userlib.DatastoreSet(UserUUID, EncryptedUserStructAndHMACBytes)
	return nil
}

func GetInvitationOfUser(userdata *User, filename string, senderusername string) (invitation *Invitation, err error) {
	invitationUUID, ok := userdata.FilesToUUID[filename]
	if !ok {
		return nil, errors.New("couldn't fetch invitation UUID")
	}

	invitationUser, err3 := FetchAndDecryptSign(invitationUUID, userdata.RSAPrivateKey, senderusername)
	if err3 != nil {
		return nil, errors.New("couldn't decrypt invitation")
	}

	var invitationUserStruct Invitation
	err4 := json.Unmarshal(invitationUser, &invitationUserStruct)
	if err4 != nil {
		return nil, errors.New("couldn't unmarshal invitation")
	}

	return &invitationUserStruct, nil
}

func GetNodeOfUserFromInvitation(invitationUserStruct Invitation) (node []byte, err error) {

	NodeUser, err1 := FetchAndDecryptHMAC(invitationUserStruct.NodeUUID, invitationUserStruct.NodeSymKey)
	if err1 != nil {
		return nil, errors.New("couldn't decrypt node in GetNodeOfUserFromInvitation")
	}

	return NodeUser, nil
}

func RemoveAllChildsOfNode(NodeUUID userlib.UUID, NodeSymKey []byte) (err error) {
	NodeToDelete, err1 := FetchAndDecryptHMAC(NodeUUID, NodeSymKey)
	if err1 != nil {
		return errors.New("couldn't decrypt node in RemoveAllChildsOfNode ")
	}
	var NodeToDeleteStruct Node
	err2 := json.Unmarshal(NodeToDelete, &NodeToDeleteStruct)
	if err2 != nil {
		return errors.New("couldn't unmarshal node in Remove")
	}
	userlib.DatastoreDelete(NodeUUID)
	for key, element := range NodeToDeleteStruct.ChildsUUIDs {
		return RemoveAllChildsOfNode(element, NodeToDeleteStruct.ChildsSymKeys[key])
	}
	return nil
}

func UpdateValueForEachNode(NodeUUID userlib.UUID, NodeSymKey []byte, newSymKeyFile []byte, newUUIDFile userlib.UUID) (err error) {
	NodeToUpdate, err1 := FetchAndDecryptHMAC(NodeUUID, NodeSymKey)
	if err1 != nil {
		return errors.New("couldn't decrypt node in UpdateValueForEachNode ")
	}
	var NodeToUpdateStruct Node
	err2 := json.Unmarshal(NodeToUpdate, &NodeToUpdateStruct)
	if err2 != nil {
		return errors.New("couldn't unmarshal node")
	}

	NodeToUpdateStruct.FileSymKey = newSymKeyFile
	NodeToUpdateStruct.FileUUID = newUUIDFile

	NodeToUpdateBytes, err1 := json.Marshal(NodeToUpdateStruct)
	if err1 != nil {
		return errors.New("couldn't marshal node")
	}

	err3 := StoreDataWithSymEncryption(NodeUUID, NodeSymKey, NodeToUpdateBytes)
	if err3 != nil {
		return errors.New("couldn't store node")
	}

	//userlib.DatastoreSet(NodeUUID, userlib.SymEnc(NodeSymKey, userlib.RandomBytes(16), NodeToUpdateBytes))

	for key, element := range NodeToUpdateStruct.ChildsUUIDs {
		fmt.Println("Key:", key, "=>", "Element:", element)
		return UpdateValueForEachNode(element, NodeToUpdateStruct.ChildsSymKeys[key], newSymKeyFile, newUUIDFile)
	}
	return nil
}

func FileContentToFilePartsUUIDs(FileContent []byte, SymKey []byte) (PartsUUIDs []userlib.UUID, err error) {
	var FileParts []FilePart
	var FilePartsUUIDs []userlib.UUID

	//creating parts
	for i := 0; i < len(FileContent); i += FileContentLength {
		//New File Part
		var FilePart FilePart
		var FileContentSlice []byte

		if i+FileContentLength < len(FileContent) {
			FileContentSlice = FileContent[i : i+FileContentLength]
		} else {
			FileContentSlice = FileContent[i:]
		}

		//storing the filepart
		FilePartUUID := uuid.New()
		FilePartsUUIDs = append(FilePartsUUIDs, FilePartUUID)

		if len(FileParts) != 0 {
			FileParts[len(FileParts)-1].NextFilePart = FilePartUUID
		}
		FilePart.Content = FileContentSlice
		FileParts = append(FileParts, FilePart)
	}

	//storing the parts
	for i := 0; i < len(FileParts); i++ {
		FilePartBytes, err1 := json.Marshal(FileParts[i])
		if err1 != nil {
			return nil, errors.New("couldn't marshal filepart")
		}
		StoreDataWithSymEncryption(FilePartsUUIDs[i], SymKey, FilePartBytes)
	}

	return FilePartsUUIDs, nil
}

func DeleteFilesPartFromFileMain(FilePartUUID userlib.UUID, SymKey []byte) (err error) {
	//fetching FileMainBytes
	FileMainBytes, err1 := FetchAndDecryptHMAC(FilePartUUID, SymKey)
	if err1 != nil {
		return errors.New("couldn't decrypt filemain")
	}
	var FileMainStruct FileMain
	err = json.Unmarshal(FileMainBytes, &FileMainStruct)
	if err != nil {
		return errors.New("couldn't unmarshal filemain")
	}

	var CurrentFilePartUUID userlib.UUID
	CurrentFilePartUUID = FileMainStruct.FirstFilePart
	//fetching FileParts
	for CurrentFilePartUUID != uuid.Nil {
		//fetching FilePart
		FilePartBytes, err1 := FetchAndDecryptHMAC(CurrentFilePartUUID, SymKey)
		if err1 != nil {
			return errors.New("couldn't decrypt filepart")
		}
		var FilePart FilePart
		err := json.Unmarshal(FilePartBytes, &FilePart)
		if err != nil {
			return errors.New("couldn't unmarshal filepart")
		}

		//deleting FilePart
		userlib.DatastoreDelete(CurrentFilePartUUID)
		CurrentFilePartUUID = FilePart.NextFilePart
	}

	return nil
}
