// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package testing

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/juju/errors"
	"github.com/juju/loggo"
	"github.com/juju/retry"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/utils"
	"github.com/juju/utils/clock"
	"github.com/juju/version"
	gc "gopkg.in/check.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	// MgoServer is a shared mongo server used by tests.
	MgoServer = &MgoInstance{}
	logger    = loggo.GetLogger("juju.testing")

	// regular expression to match output of mongod
	waitingForConnectionsRe = regexp.MustCompile(".*initandlisten.*waiting for connections.*")

	// After version 3.2 we shouldn't use --nojournal - it makes the
	// WiredTiger storage engine much slower.
	// https://jira.mongodb.org/browse/SERVER-21198
	useJournalMongoVersion = version.Number{Major: 3, Minor: 2}
	// mongoVersion           lazyMongoVersion
)

const (
	// Maximum number of times to attempt starting mongod.
	maxStartMongodAttempts = 5
	// The default password to use when connecting to the mongo database.
	DefaultMongoPassword = "conn-from-name-secret"
)

// Certs holds the certificates and keys required to make a secure
// SSL connection.
type Certs struct {
	// CACert holds the CA certificate. This must certify the private key that
	// was used to sign the server certificate.
	CACert *x509.Certificate
	// ServerCert holds the certificate that certifies the server's
	// private key.
	ServerCert *x509.Certificate
	// ServerKey holds the server's private key.
	ServerKey *rsa.PrivateKey
}

type MgoInstance struct {
	// addr holds the address of the MongoDB server
	addr string

	// MgoPort holds the port of the MongoDB server.
	port int

	// server holds the running MongoDB command.
	server *exec.Cmd

	// exited receives a value when the mongodb server exits.
	exited <-chan struct{}

	// dir holds the directory that MongoDB is running in.
	dir string

	// certs holds certificates for the TLS connection.
	certs *Certs

	// Params is a list of additional parameters that will be passed to
	// the mongod application
	Params []string

	// EnableAuth enables authentication/authorization.
	EnableAuth bool

	// WithoutV8 is true if we believe this Mongo doesn't actually have the
	// V8 engine
	WithoutV8 bool
}

// Addr returns the address of the MongoDB server.
func (m *MgoInstance) Addr() string {
	//return m.addr
	return fmt.Sprintf("127.0.0.1:%d", m.Port())
}

// Port returns the port of the MongoDB server.
func (m *MgoInstance) Port() int {
	//return m.port
	return 27017
}

// We specify a timeout to mgo.Dial, to prevent
// mongod failures hanging the tests.
const mgoDialTimeout = 1 * time.Second

// MgoSuite is a suite that deletes all content from the shared MongoDB
// server at the end of every test and supplies a connection to the shared
// MongoDB server.
type MgoSuite struct {
	Session *mgo.Session
}

// generatePEM receives server certificate and the server private key
// and creates a PEM file in the given path.
func generatePEM(path string, serverCert *x509.Certificate, serverKey *rsa.PrivateKey) error {
	pemFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to open %q for writing: %v", path, err)
	}
	defer pemFile.Close()
	err = pem.Encode(pemFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCert.Raw,
	})
	if err != nil {
		return fmt.Errorf("failed to write cert to %q: %v", path, err)
	}
	err = pem.Encode(pemFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})
	if err != nil {
		return fmt.Errorf("failed to write private key to %q: %v", path, err)
	}
	return nil
}

func (i *MgoInstance) Start(certs *Certs) error {
	i.addr = i.Addr()
	i.port = i.Port()
	i.certs = certs
	return nil
}

// The mongod --version line starts with this prefix.
const versionLinePrefix = "db version v"

// Destroy kills mongod and cleans up its data directory.
func (inst *MgoInstance) Destroy() {
	if err := inst.Reset(); err != nil {
		panic(err)
	}
}

// MgoTestPackage should be called to register the tests for any package
// that requires a MongoDB server. If certs is non-nil, a secure SSL connection
// will be used from client to server.
func MgoTestPackage(t *testing.T, certs *Certs) {
	if err := MgoServer.Start(certs); err != nil {
		t.Fatal(err)
	}
	// defer MgoServer.Destroy()
	defer func() {
		if err := MgoServer.Reset(); err != nil {
			panic(err)
		}
	}()
	gc.TestingT(t)
}

type mgoLogger struct {
	logger loggo.Logger
}

// Output implements the mgo log_Logger interface.
func (s *mgoLogger) Output(calldepth int, message string) error {
	s.logger.LogCallf(calldepth, loggo.TRACE, message)
	return nil
}

func namespaceFormat(instanceNum int) string {
	return fmt.Sprintf("mongo-instance-%v", instanceNum)
}

func (s *MgoSuite) SetUpSuite(c *gc.C) {
	mgo.SetLogger(&mgoLogger{loggo.GetLogger("mgo")})
	mgo.SetDebug(true)
	if MgoServer.addr == "" {
		c.Fatalf("No Mongo Server Address, MgoSuite tests must be run with MgoTestPackage")
	}
	mgo.SetStats(true)
	// Make tests that use password authentication faster.
	utils.FastInsecureHash = true
	mgo.ResetStats()
	fmt.Printf("KT: %+v", MgoServer)
	session, err := MgoServer.Dial()
	c.Assert(err, jc.ErrorIsNil)
	defer session.Close()
	err = dropAll(session)
	c.Assert(err, jc.ErrorIsNil)
}

// readUntilMatching reads lines from the given reader until the reader
// is depleted or a line matches the given regular expression.
func readUntilMatching(prefix string, r io.Reader, re *regexp.Regexp) bool {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		logger.Tracef("%s: %s", prefix, line)
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// readLastLines reads lines from the given reader and returns
// the last n non-empty lines, ignoring empty lines.
func readLastLines(prefix string, r io.Reader, n int) []string {
	sc := bufio.NewScanner(r)
	lines := make([]string, n)
	i := 0
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\n"); line != "" {
			logger.Tracef("%s: %s", prefix, line)
			lines[i%n] = line
			i++
		}
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}
	final := make([]string, 0, n+1)
	if i > n {
		final = append(final, fmt.Sprintf("[%d lines omitted]", i-n))
	}
	for j := 0; j < n; j++ {
		if line := lines[(j+i)%n]; line != "" {
			final = append(final, line)
		}
	}
	return final
}

func (s *MgoSuite) TearDownSuite(c *gc.C) {
	err := MgoServer.Reset()
	c.Assert(err, jc.ErrorIsNil)
	utils.FastInsecureHash = false
	mgo.SetDebug(false)
	mgo.SetLogger(nil)
}

// MustDial returns a new connection to the MongoDB server, and panics on
// errors.
func (inst *MgoInstance) MustDial() *mgo.Session {
	s, err := mgo.DialWithInfo(inst.DialInfo())
	if err != nil {
		panic(err)
	}
	return s
}

// Dial returns a new connection to the MongoDB server.
func (inst *MgoInstance) Dial() (*mgo.Session, error) {
	var session *mgo.Session
	err := retry.Call(retry.CallArgs{
		Func: func() error {
			var err error
			session, err = mgo.DialWithInfo(inst.DialInfo())
			return errors.Trace(err)
		},
		// Only interested in retrying the intermittent
		// 'unexpected message'.
		IsFatalError: func(err error) bool {
			return !strings.HasSuffix(err.Error(), "unexpected message")
		},
		Delay:    time.Millisecond,
		Clock:    clock.WallClock,
		Attempts: 5,
	})
	return session, errors.Trace(err)
}

// DialInfo returns information suitable for dialling the
// receiving MongoDB instance.
func (inst *MgoInstance) DialInfo() *mgo.DialInfo {
	return MgoDialInfo(nil, inst.addr)
}

// DialDirect returns a new direct connection to the shared MongoDB server. This
// must be used if you're connecting to a replicaset that hasn't been initiated
// yet.
func (inst *MgoInstance) DialDirect() (*mgo.Session, error) {
	info := inst.DialInfo()
	info.Direct = true
	return mgo.DialWithInfo(info)
}

// MustDialDirect works like DialDirect, but panics on errors.
func (inst *MgoInstance) MustDialDirect() *mgo.Session {
	session, err := inst.DialDirect()
	if err != nil {
		panic(err)
	}
	return session
}

// MgoDialInfo returns a DialInfo suitable
// for dialling an MgoInstance at any of the
// given addresses, optionally using TLS.
func MgoDialInfo(certs *Certs, addrs ...string) *mgo.DialInfo {
	var dial func(addr net.Addr) (net.Conn, error)
	if certs != nil {
		pool := x509.NewCertPool()
		pool.AddCert(certs.CACert)
		tlsConfig := &tls.Config{
			RootCAs:    pool,
			ServerName: "anything",
		}
		dial = func(addr net.Addr) (net.Conn, error) {
			conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
			if err != nil {
				logger.Debugf("tls.Dial(%s) failed with %v", addr, err)
				return nil, err
			}
			return conn, nil
		}
	} else {
		dial = func(addr net.Addr) (net.Conn, error) {
			conn, err := net.Dial("tcp", addr.String())
			if err != nil {
				logger.Debugf("net.Dial(%s) failed with %v", addr, err)
				return nil, err
			}
			return conn, nil
		}
	}
	return &mgo.DialInfo{Addrs: addrs, Dial: dial, Timeout: mgoDialTimeout}
}

func clearDatabases(session *mgo.Session) error {
	databases, err := session.DatabaseNames()
	if err != nil {
		return errors.Trace(err)
	}
	for _, name := range databases {
		err = clearCollections(session.DB(name))
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func clearCollections(db *mgo.Database) error {
	collectionNames, err := db.CollectionNames()
	if err != nil {
		return errors.Trace(err)
	}
	for _, name := range collectionNames {
		if strings.HasPrefix(name, "system.") {
			continue
		}
		collection := db.C(name)
		clearFunc := clearNormalCollection
		capped, err := isCapped(collection)
		if err != nil {
			return errors.Trace(err)
		}
		if capped {
			clearFunc = clearCappedCollection
		}
		err = clearFunc(collection)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func isCapped(collection *mgo.Collection) (bool, error) {
	result := bson.M{}
	err := collection.Database.Run(bson.D{{"collstats", collection.Name}}, &result)
	if err != nil {
		return false, errors.Trace(err)
	}
	value, found := result["capped"]
	if !found {
		return false, nil
	}
	capped, ok := value.(bool)
	if !ok {
		return false, errors.Errorf("unexpected type for capped: %v", value)
	}
	return capped, nil
}

func clearNormalCollection(collection *mgo.Collection) error {
	_, err := collection.RemoveAll(bson.M{})
	return err
}

func clearCappedCollection(collection *mgo.Collection) error {
	// This is a test command - relies on the enableTestCommands
	// setting being passed to mongo at startup.
	return collection.Database.Run(bson.D{{"emptycapped", collection.Name}}, nil)
}

func (s *MgoSuite) SetUpTest(c *gc.C) {
	s.Session = nil
	mgo.ResetStats()
	session, err := MgoServer.Dial()
	c.Assert(err, jc.ErrorIsNil)
	s.Session = session

	names, err := s.Session.DatabaseNames()
	if err != nil {
		panic(err)
	}
	c.Logf("KT: dbs: %+v", names)
}

// Reset deletes all content from the MongoDB server.
func (inst *MgoInstance) Reset() error {
	session, err := inst.Dial()
	if err != nil {
		return errors.Annotate(err, "inst.Dial() failed")
	}
	defer session.Close()

	return errors.Trace(dropAll(session))
}

// dropAll drops all databases apart from admin, local and config.
func dropAll(session *mgo.Session) (err error) {
	names, err := session.DatabaseNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		switch name {
		case "admin", "local", "config":
		default:
			err = session.DB(name).DropDatabase()
			if err != nil {
				return errors.Annotatef(err, "cannot drop MongoDB database %v", name)
			}
		}
	}
	return nil
}

// resetAdminPasswordAndFetchDBNames logs into the database with a
// plausible password and returns all the database's db names. We need
// to try several passwords because we don't know what state the mongo
// server is in when Reset is called. If the test has set a custom
// password, we're out of luck, but if they are using
// DefaultStatePassword, we can succeed.
func resetAdminPasswordAndFetchDBNames(session *mgo.Session) ([]string, bool, error) {
	// First try with no password
	dbnames, err := session.DatabaseNames()
	if err == nil {
		return dbnames, true, nil
	}
	if !isUnauthorized(err) {
		return nil, false, errors.Trace(err)
	}
	// Then try the two most likely passwords in turn.
	for _, password := range []string{
		DefaultMongoPassword,
		utils.UserPasswordHash(DefaultMongoPassword, utils.CompatSalt),
	} {
		admin := session.DB("admin")
		if err := admin.Login("admin", password); err != nil {
			logger.Errorf("failed to log in with password %q", password)
			continue
		}
		dbnames, err := session.DatabaseNames()
		if err == nil {
			return dbnames, true, nil
		}
		if !isUnauthorized(err) {
			return nil, false, errors.Trace(err)
		}
		logger.Infof("unauthorized access when getting database names; password %q", password)
	}
	return nil, false, errors.Trace(err)
}

// isUnauthorized is a copy of the same function in state/open.go.
func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	// Some unauthorized access errors have no error code,
	// just a simple error string.
	if err.Error() == "auth fails" {
		return true
	}
	if err, ok := err.(*mgo.QueryError); ok {
		return err.Code == 10057 ||
			err.Message == "need to login" ||
			err.Message == "unauthorized"
	}
	return false
}

func (s *MgoSuite) TearDownTest(c *gc.C) {
	if s.Session == nil {
		c.Fatal("SetUpTest failed")
	}

	var err error
	// If the Session we have doesn't know about
	// the address of the server, then we should reconnect.
	foundAddress := false
	for _, addr := range s.Session.LiveServers() {
		if addr == MgoServer.Addr() {
			foundAddress = true
			break
		}
	}

	if !foundAddress {
		// The test has killed the server - reconnect.
		s.Session.Close()
		s.Session, err = MgoServer.Dial()
		c.Assert(err, jc.ErrorIsNil)
	}

	// Rather than dropping the databases (which is very slow in Mongo
	// 3.2) we clear all of the collections.
	err = clearDatabases(s.Session)
	c.Assert(err, jc.ErrorIsNil)
	s.Session.Close()
	s.Session = nil
}

// ProxiedSession represents a mongo session that's
// proxied through a TCPProxy instance.
type ProxiedSession struct {
	*mgo.Session
	*TCPProxy
}

// NewProxiedSession returns a ProxiedSession instance that holds a
// mgo.Session that directs through a TCPProxy instance to the testing
// mongoDB server, and the proxy instance itself. This allows tests to
// check what happens when mongo connections are broken.
//
// The returned value should be closed after use.
func NewProxiedSession(c *gc.C) *ProxiedSession {
	mgoInfo := MgoServer.DialInfo()
	c.Assert(mgoInfo.Addrs, gc.HasLen, 1)
	proxy := NewTCPProxy(c, mgoInfo.Addrs[0])
	mgoInfo.Addrs = []string{proxy.Addr()}
	session, err := mgo.DialWithInfo(mgoInfo)
	c.Assert(err, gc.IsNil)
	err = session.Ping()
	c.Assert(err, jc.ErrorIsNil)
	return &ProxiedSession{
		Session:  session,
		TCPProxy: proxy,
	}
}

// Close closes s.Session and s.TCPProxy.
func (s *ProxiedSession) Close() {
	s.Session.Close()
	s.TCPProxy.Close()
}

// FindTCPPort finds an unused TCP port and returns it.
// Use of this function has an inherent race condition - another
// process may claim the port before we try to use it.
// We hope that the probability is small enough during
// testing to be negligible.
func FindTCPPort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type addrAlreadyInUseError struct {
	error
}

// IsolatedMgoSuite is a convenience type that combines the functionality
// IsolationSuite and MgoSuite.
type IsolatedMgoSuite struct {
	IsolationSuite
	MgoSuite
}

func (s *IsolatedMgoSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)
	s.MgoSuite.SetUpSuite(c)
}

func (s *IsolatedMgoSuite) TearDownSuite(c *gc.C) {
	s.MgoSuite.TearDownSuite(c)
	s.IsolationSuite.TearDownSuite(c)
}

func (s *IsolatedMgoSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.MgoSuite.SetUpTest(c)
}

func (s *IsolatedMgoSuite) TearDownTest(c *gc.C) {
	s.MgoSuite.TearDownTest(c)
	s.IsolationSuite.TearDownTest(c)
}
