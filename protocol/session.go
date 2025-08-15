package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"strings"

	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"
)

const (
	// Message retry timeout
	messageRetryTimeout = 10 * time.Second
)

type TaskAgentMessage struct {
	MessageID   int64
	MessageType string
	IV          string
	Body        string
}

func (message *TaskAgentMessage) Decrypt(block cipher.Block) ([]byte, error) {
	if message.IV == "" {
		return []byte(message.Body), nil
	}
	iv, err := base64.StdEncoding.DecodeString(message.IV)
	if err != nil {
		return nil, err
	}
	src, err := base64.StdEncoding.DecodeString(message.Body)
	if err != nil {
		return nil, err
	}
	cbcdec := cipher.NewCBCDecrypter(block, iv)
	cbcdec.CryptBlocks(src, src)
	maxlen := block.BlockSize()
	validlen := len(src)
	// <= is needed if the message ends within a block boundary and maxlen=16
	// then we get 16 times char 16 appended, one whole extra block
	if int(src[len(src)-1]) <= maxlen {
		ok := true
		for i := 2; i <= int(src[len(src)-1]); i++ {
			if src[len(src)-i] != src[len(src)-1] {
				ok = false
				break
			}
		}
		if ok {
			validlen -= int(src[len(src)-1])
		}
	}
	off := 0
	// skip utf8 bom, c# cryptostream uses it for utf8
	if src[0] == 239 && src[1] == 187 && src[2] == 191 {
		off = 3
	}
	return src[off:validlen], nil
}

type BrokerMigration struct {
	BrokerBaseURL string `json:"brokerBaseUrl"`
}

func (message *TaskAgentMessage) FetchBrokerIfNeeded(xctx context.Context, session *AgentMessageConnection) error {
	if strings.EqualFold(message.MessageType, "BrokerMigration") {
		vssConnection := session.VssConnection
		rjrr := &BrokerMigration{}
		raw, err := message.Decrypt(session.Block)
		if err != nil {
			return err
		}
		err = json.Unmarshal(raw, rjrr)
		if err != nil {
			return err
		}
		for retries := 0; retries < 5; retries++ {
			connCopy := *vssConnection
			vssConnection := &connCopy
			vssConnection.TenantURL = rjrr.BrokerBaseURL
			furl, urlErr := vssConnection.BuildURL("message", map[string]string{}, map[string]string{
				"sessionId":     session.TaskAgentSession.SessionID,
				"runnerVersion": "3.0.0",
				"status":        session.Status,
			})
			if urlErr != nil {
				return urlErr
			}
			err = vssConnection.RequestWithContext2(xctx, "GET", furl, "", nil, &message)
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			select {
			case <-xctx.Done():
				return xctx.Err()
			case <-time.After(time.Second * 5 * time.Duration(retries+1)):
			}
		}
		return err
	}
	return nil
}

type TaskAgentSessionKey struct {
	Encrypted bool
	Value     string
}

type TaskAgentSession struct {
	SessionID         string `json:",omitempty"`
	EncryptionKey     TaskAgentSessionKey
	OwnerName         string
	Agent             TaskAgent
	UseFipsEncryption bool
}

func (session *TaskAgentSession) GetSessionKey(key *rsa.PrivateKey) (cipher.Block, error) {
	sessionKey, err := base64.StdEncoding.DecodeString(session.EncryptionKey.Value)
	if sessionKey == nil || err != nil {
		return nil, err
	}
	if session.EncryptionKey.Encrypted {
		var h hash.Hash
		if session.UseFipsEncryption {
			h = sha256.New()
		} else {
			h = sha1.New()
		}
		sessionKey, err = rsa.DecryptOAEP(h, rand.Reader, key, sessionKey, []byte{})
		if sessionKey == nil || err != nil {
			return nil, err
		}
	}
	return aes.NewCipher(sessionKey)
}

type AgentMessageConnection struct {
	VssConnection    *VssConnection
	TaskAgentSession *TaskAgentSession
	Block            cipher.Block
	Status           string
}

func (session *AgentMessageConnection) Delete(ctx context.Context) error {
	return session.VssConnection.RequestWithContext(ctx, "134e239e-2df3-4794-a6f6-24f1f19ec8dc", "5.1-preview", "DELETE", map[string]string{
		"poolId":    fmt.Sprint(session.VssConnection.PoolID),
		"sessionId": session.TaskAgentSession.SessionID,
	}, map[string]string{}, session.TaskAgentSession, nil)
}

func (session *AgentMessageConnection) GetNextMessage(ctx context.Context) (*TaskAgentMessage, error) {
	message := &TaskAgentMessage{}
	for {
		select {
		case <-ctx.Done():
			return nil, context.Canceled
		default:
		}
		err := session.VssConnection.RequestWithContext(ctx, "c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "GET", map[string]string{
			"poolId": fmt.Sprint(session.VssConnection.PoolID),
		}, map[string]string{
			"sessionId":     session.TaskAgentSession.SessionID,
			"runnerVersion": "3.0.0",
		}, nil, message)
		// TODO lastMessageId=
		if err == nil {
			err = session.DeleteMessage(ctx, message)
			err = errors.Join(err, message.FetchBrokerIfNeeded(ctx, session))
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			} else if !errors.Is(err, io.EOF) {
				fmt.Printf("Failed to get message, waiting 10 sec before retry: %v\n", err.Error())
				select {
				case <-ctx.Done():
					return nil, context.Canceled
				case <-time.After(messageRetryTimeout):
				}
			}
		} else {
			return message, nil
		}
	}
}

func (session *AgentMessageConnection) DeleteMessage(ctx context.Context, message *TaskAgentMessage) error {
	return session.VssConnection.RequestWithContext(ctx, "c3a054f6-7a8a-49c0-944e-3a8e5d7adfd7", "5.1-preview", "DELETE", map[string]string{
		"poolId":    fmt.Sprint(session.VssConnection.PoolID),
		"messageId": fmt.Sprint(message.MessageID),
	}, map[string]string{
		"sessionId": session.TaskAgentSession.SessionID,
	}, nil, nil)
}
