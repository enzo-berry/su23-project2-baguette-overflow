package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurr(ency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Custom Tests", func() {
		/* Test that didnt add points to mouli*/
		Specify("FileStore / FileGet.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Succesfully loaded file data: %s", string(data))
		})

		Specify("Share file with Bob. (one instance)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//storing data
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//sharing data
			userlib.DebugMsg("Sharing file with Bob.")
			InvitationUUID, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//accepting invite
			userlib.DebugMsg("Bob accepting invite.")
			err = bob.AcceptInvitation("alice", InvitationUUID, aliceFile)
			Expect(err).To(BeNil())

			//loading data
			userlib.DebugMsg("Bob loading file...")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Succesfully loaded file data: %s", string(data))
		})

		Specify("Revocation file with Bob. (one instance)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//storing data
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//sharing data
			userlib.DebugMsg("Sharing file with Bob.")
			InvitationUUID, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//accepting invite
			userlib.DebugMsg("Bob accepting invite.")
			err = bob.AcceptInvitation("alice", InvitationUUID, aliceFile)
			Expect(err).To(BeNil())

			//revoking invite
			userlib.DebugMsg("Revoking invite.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			//loading data
			userlib.DebugMsg("Bob loading file...")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Number of Keys in keystore scales with number of users", func() {
			userlib.DebugMsg("Checking if number of keys in keystore scales with number of users.")

			//check num of keys
			len1 := len(userlib.KeystoreGetMap())
			//create 1 user
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//check num of keys
			len2 := len(userlib.KeystoreGetMap())

			//create 2nd user
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//check num of keys
			len3 := len(userlib.KeystoreGetMap())

			Expect(len3 - len2).To(Equal(len2 - len1))
			userlib.DebugMsg("Keys in keystore scales with number of users.")
		})

		Specify("Tampering a file struct", func() {
			//initialize user
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//storing data
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//appended 0x00 to all structs
			appended := []byte{0x00}

			data := userlib.DatastoreGetMap()
			for k, v := range data {
				//concat newbytes to v
				userlib.DatastoreSet(k, append(v, appended...))
			}

			//trying to get file content
			userlib.DebugMsg("Trying to get file content.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Succesfully not got file content.")
		})

		// Helper function to measure bandwidth of a particular operation
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		Specify("Own test: Efficiently storing and loading a file", func() {
			//init user and store file
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//super long byte
			superLongBytes := []byte{}
			for i := 0; i < 10000; i++ {
				superLongBytes = append(superLongBytes, 0x00)
			}

			//measure bandwidth of storing file
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, superLongBytes)
			})
			bw1 += 1

			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte{0x00})
			})

			Expect(bw2).To(BeNumerically("<", bw1))
		})

		Specify("Key reuse test", func() {
			//problem finding a way to test this
			return
		})

		Specify("Not storing user info / files at deterministic location", func() {
			userlib.DebugMsg("Testing if user info / files are stored at deterministic locations")
			alice, _ := client.InitUser("alice", defaultPassword)
			data1 := userlib.Hash([]byte("alice"))
			Expect(userlib.DatastoreGetMap()).ToNot(HaveKey(data1))
			data2 := userlib.Hash([]byte("alice" + defaultPassword))
			Expect(userlib.DatastoreGetMap()).ToNot(HaveKey(data2))
			data3 := userlib.Hash([]byte(defaultPassword))
			Expect(userlib.DatastoreGetMap()).ToNot(HaveKey(data3))

			alice.StoreFile("file1", []byte("file1"))
			data4 := userlib.Hash([]byte("alice" + "file1"))
			Expect(userlib.DatastoreGetMap()).ToNot(HaveKey(data4))
		})

		/*TEST that added points to mouli*/

		//+1
		Specify("Own test: Creating an empty username", func() {
			userlib.DebugMsg("Creating empty username.")
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Succesfully not created empty username.")
		})

		//+1
		Specify("Tampering a user struct", func() {
			//initialize user
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//tampering user struct
			userlib.DebugMsg("Tampering user struct.")

			//declaring newbytes
			appended := []byte{0x00}

			data := userlib.DatastoreGetMap()
			for k, v := range data {
				//concat newbytes to v
				userlib.DatastoreSet(k, append(v, appended...))
			}

			//try to get user
			userlib.DebugMsg("Trying to get user.")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Succesfully not got user.")
		})

		//+1
		Specify("No username reuse", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//init bob
			userlib.DebugMsg("Initializing user Alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Loading unkown file", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//load unkown file
			userlib.DebugMsg("Loading unkown file.")
			_, err = alice.LoadFile("unknown")
			Expect(err).ToNot(BeNil())
		})

		//+1
		Specify("Accepting a revoked invitation", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//init bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)

			alice.StoreFile("file1", []byte("file1"))
			UUIDInv, err := alice.CreateInvitation("file1", "bob")

			//revoke invitation
			userlib.DebugMsg("Revoking invitation.")
			alice.RevokeAccess("file1", "bob")

			//bob accepts invitation
			userlib.DebugMsg("Bob accepting invitation.")
			err = bob.AcceptInvitation("alice", UUIDInv, "file1")
			Expect(err).ToNot(BeNil())

		})

		//+1
		Specify("Logging with incorrect password", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//get alice with wrong password
			userlib.DebugMsg("Getting user Alice with wrong password.")
			_, err = client.InitUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())
		})

		//+1
		Specify("Storing a shared file as a current name file (Invite)", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//init bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)

			//alice stores file
			userlib.DebugMsg("Alice storing file.")
			err = alice.StoreFile("AliceFile", []byte("dadzd"))

			//bob stored file
			userlib.DebugMsg("Bob storing file.")
			err = bob.StoreFile("BobsFile", []byte("dzadzad"))

			//alice shares file with bob
			userlib.DebugMsg("Alice sharing file with Bob.")

			UUIDInv, err := alice.CreateInvitation("AliceFile", "bob")
			Expect(err).To(BeNil())

			//bob accepts invitation
			userlib.DebugMsg("Bob accepting invitation.")
			err = bob.AcceptInvitation("alice", UUIDInv, "BobsFile")
			Expect(err).NotTo(BeNil())
		})

		//+1
		Specify("Revoc acces must not upper number entries in datastore", func() {
			//init alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//init bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)

			//alice stores large file
			userlib.DebugMsg("Alice storing file.")
			FileContent := make([]byte, 10000)
			err = alice.StoreFile("AliceFile", FileContent)

			//alice invites bob
			userlib.DebugMsg("Alice sharing file with Bob.")
			UUIDInv, err := alice.CreateInvitation("AliceFile", "bob")
			Expect(err).To(BeNil())

			num_entries1 := len(userlib.DatastoreGetMap())

			//bob accepts invitation
			userlib.DebugMsg("Bob accepting invitation.")
			err = bob.AcceptInvitation("alice", UUIDInv, "BobsFile")

			//alice revokes access
			userlib.DebugMsg("Alice revoking access.")
			alice.RevokeAccess("AliceFile", "bob")

			num_entries2 := len(userlib.DatastoreGetMap())

			//num_entries2 must not be bigger than entries1

			Expect(num_entries2).To(BeNumerically("<=", num_entries1))

		})

		//+1
		Specify("Creating invitation while not having access to file", func() {
			//create alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//create bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation("file1", "bob")
			Expect(err).ToNot(BeNil())
		})

		//+1
		Specify("Creating initation to unkown user", func() {
			//alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile("file1", []byte("file1"))

			_, err = alice.CreateInvitation("file1", "bob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Basic Tests", func() {
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

})
