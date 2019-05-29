package uua_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/pzl/uua"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

type UUATestSuite struct {
	suite.Suite
	secrets uua.Secrets
}

func TestExampleTestSuite(t *testing.T) { suite.Run(t, new(UUATestSuite)) }

func createRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func (suite *UUATestSuite) SetupSuite() {
	suite.secrets = uua.Secrets{
		Key:  createRSAKey(),
		Pass: []byte("testpass"),
		Salt: []byte("testsalt"),
	}
}

func (suite *UUATestSuite) TestNew() {
	t := uua.New("u", "testapp", 7, 30*time.Minute)
	suite.Equal("u", t.User)
	suite.Equal("testapp", t.App)
	suite.Equal(uint64(7), t.Generation)
	suite.WithinDuration(time.Now().Add(30*time.Minute), t.Expiration, 5*time.Second)
	suite.Equal(uua.CURRENT_VERSION, t.Version)
}
func (suite *UUATestSuite) TestNewDefaultExpir() {
	t := uua.New("u", "testapp", 1, 0)
	suite.WithinDuration(time.Now().Add(uua.DEFAULT_EXP), t.Expiration, 5*time.Second)
}
func (suite *UUATestSuite) TestNewAboveMaxExpr() {
	t := uua.New("u", "testapp", 1, 24*1000*time.Hour)
	suite.WithinDuration(time.Now().Add(uua.DEFAULT_EXP), t.Expiration, 5*time.Second)
}

func (suite *UUATestSuite) TestEncode() {
	t := uua.New("us", "appsds34", 1, 30*time.Minute)

	enc, err := t.Encode(suite.secrets)
	suite.NoError(err)

	suite.Contains(enc, ".")
}

func (suite *UUATestSuite) TestDecode() {
	keyS := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4+nPSOzzkXc8JZSB0G1AkLqZWwhs6nSdFEWGfSrd+egW6ZB0
5y7Dppms4gJwfrGtvLVUxAT0xBes4+FzK+0/Q0oDy4RbvIGuMfCEFmaEi1QKzkFF
07SUK01tGkJYbkuf7UzTqVXADqOMveMiFqfbalxQ61GLLh2vyqmKlzcpDvGtdy3t
44ee+TNk9xQnTA97XKuJ1IUOzTtMiWYp6sTmXd8OZt4+ewBg0W58eRIoDjSgzjoo
6OyNjV+GkIg6QQSIK/8K4BaF3IVXsXaFUQkcCoOZpgDrMOsPGQz5Bzt+hr1XlH12
aiT7hjtpdLE7T3kAtHntWuVSczDqLJvB0ZC0rQIDAQABAoIBAQCCgUSflocWGbeI
MVRwG88n0KG1vcpYKnQzwmfzTlOTITHVhlFae62uvTqApDL0aRt5/j9OiyP5ETF/
v33qfkyGZGBt7hl1hLBRik6oYQWunm4dksTAKBvb+9bofWsTpRwrjp14zlBOUZpq
tR+052M9sSToymWu/3LE0nY4hm5tTiNWyX1BjGl6H2msU0Is8uQhIuiXOkY3Y4nb
C4DPDk5xS97eTeak8xbBrFadXAX31be228N3586pnEYr1yhbIOHBoANNm/VQ1MiE
K55BcyCx74yXmjWzJgUIgOo61gW2Ef13cabnahfYxs7v1qgITr9gNN5kJun8HI/b
ObXFfkKlAoGBAPsXhkpNui2kvgt1jnt5qW+5NKF9e2nYfzbG2Cz3VtUh9PjdihBs
lvqMGNKvIgrct43pJp1QYT0PwfzXz/IkuflW2BNQDywQRlLCk+PKo9xUwlY9SVgl
Npxw0kg6DN5WMO0HTXPBjV+D+MUA7Vq9cMeB9f5OafxCIr4/JgzfL2JHAoGBAOhe
TGlQQAqK+oZ7ytchvDQlW3VtNZSLjv3VBMh7IKTRj6Pigt5MH4Wa0v9UMKqDhbaV
8pLShvjOzTB+AnQKaOiheOBYDDAazgj1Uvf9ge7wocAB4yZTMSQ5TtEOc3JaiBgp
hxgzgq2xE7Qvgmqi3OaPE/3U0+xN3eFveoQkf9drAoGAAJn8016+TG+xmNtuPPN8
qWzbKGvhiM5g96OgTvNEvPv410PImeN4tR7yzEZpIXeH5Qoi8ouHwBqyj0WBFQZr
f6JqoBk4ABYF5RrcOdZ5cASv9n7tFw33xIYsqsmg0EOKmHbFA7r5+LmbNfWbm/UK
OSAhk7tiW51Y8fW6xJsgRO8CgYA16htEnDAfwhtatMJdpCAs4TYVSt+RtcfZsWFI
uvjaBR2U4uuGdJcjwsaOI5SfG6EcujHsSxiyBhmp1LLxBbFNuJl5RDSfvLhtb65u
h81sCT0eddGkhMz0IK/e5cF3mPXW1VvZC6qYbmup9RQHdf5XKH9097qsK2z974W3
v1hCPQKBgBvfjWWMRnvLK31LhuWDRbJdDefUCh0iNUb1IOuphNS1Bl5rWS+JriLj
AEXb8OFXzAvVEOcJjuNWK/G2qO+D4uV3jQG2DZAkH6c4BRNq7NhiCo4dwjiG5kMB
kpyZ2jezIDM23yv12txtoCD/jz0Qz0onOQD9sgY2HiGVdtUmiaEZ
-----END RSA PRIVATE KEY-----`
	ts := "ttN86FtoLv2YhnPa+dAqJ5GCfxb5u2eoyp+uyEfODRNLV00UQLH9y8WsvpDjrzpSrF5CdNue0XVzsZwQebkpM6sYmP4X43VwFfAfED4J4vmnzwaT59E/aHk=.vvJm81Q/zsgDzQQqQTT0DjQN7l0ouc9WAmavHlmH5cb1yxnlGZixjqk8V3RdjaApW5WORutsNg6DemSR0TpODIg4cd7wLuaRCd/23uTyYp3TH8Aruak87ykuoKYIrGCXVHZifNTtBeoB4qwHpH+4um9XujKRY2SxQxOIFmAGFjtaK4aSPqKsusZd55/hEL+2KxnLpcB5bN3JIe1L4VlHarvEDFQ6LTSPBwXwUSaUgFvILkP2FsQL/yPMyimtYKcNRpX5XxDfJJ4VLUer3Vue9sIf0Fj480HVk63D2zWyr37Ik7fCsl051CGQERz4k2piaXyHlNHPd+U5+4Eb121TkA=="

	k, err := ssh.ParseRawPrivateKey([]byte(keyS))
	suite.NoError(err)
	key, ok := k.(*rsa.PrivateKey)
	suite.True(ok)

	sec := uua.Secrets{
		Pass: []byte("decodepass"),
		Salt: []byte("saltlick"),
		Key:  key,
	}

	t, err := uua.Decode(ts, sec)
	suite.NoError(err)
	suite.NotNil(t)

	suite.Equal("decodeuser", t.User)
	suite.Equal("decodeapp", t.App)
	suite.Equal(uint64(4), t.Generation)
	suite.Equal(1, t.Version)
	suite.Equal(int64(1559156902), t.Expiration.Unix())
}

func (suite *UUATestSuite) TestGenerationIgnore() {
	t := uua.New("u", "", 70, 0)

	enc, err := t.Encode(suite.secrets)
	suite.NoError(err)

	ok, t2 := uua.Validate(enc, suite.secrets, 0)
	suite.True(ok)
	suite.NotNil(t2)
}

func (suite *UUATestSuite) TestGenerationRevoked() {
	gen := 5
	t := uua.New("u", "", uint64(gen), 0)

	enc, err := t.Encode(suite.secrets)
	suite.NoError(err)

	ok, t2 := uua.Validate(enc, suite.secrets, uint64(gen+1))
	suite.False(ok)
	suite.Nil(t2)
}

func (suite *UUATestSuite) TestRoundTrip() {
	user := "sd45w2"
	app := "er235d"
	gen := uint64(8)
	exp := 23 * time.Minute

	t := uua.New(user, app, gen, exp)

	enc, err := t.Encode(suite.secrets)
	suite.NoError(err)

	ok, t2 := uua.Validate(enc, suite.secrets, gen)

	suite.True(ok)
	suite.Equal(t2.User, t.User)
	suite.Equal(t2.App, t.App)
	suite.Equal(t2.Version, t.Version)
	suite.Equal(t2.Generation, t.Generation)
	suite.Equal(t2.Expiration.Unix(), t.Expiration.Unix())
}
