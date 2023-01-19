package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
	"github.com/hoophq/pluginhooks"
)

type secretManager struct {
	logger hclog.Logger
	params *pluginhooks.SesssionParams
}

func getAWSSecretValue(svc *secretsmanager.SecretsManager, secretID string) (map[string]string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf("code=%s, err=%s", aerr.Code(), aerr)
		}
		return nil, err
	}
	var keyValSecret map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &keyValSecret); err != nil {
		return nil, fmt.Errorf("failed deserializing secret key/val")
	}
	return keyValSecret, nil
}

func newAWSSecretsManagerClient(accessKeyID, secretKey, region string) (*secretsmanager.SecretsManager, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretKey, ""),
	})
	if err != nil {
		return nil, err
	}
	return secretsmanager.New(sess), nil
}

type valAttr struct {
	provider  string
	secretID  string
	secretKey string
}

func parseAWSConnectionVal(val string) (*valAttr, error) {
	parts := strings.SplitN(val, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("failed parsing connection value, want=provider:secret-id:key, got=%s", val)
	}
	return &valAttr{parts[0], parts[1], parts[2]}, nil
}

func (s *secretManager) logRedactVal(envKey string, val string) {
	redactVal := "#######"
	if len(val) > 8 {
		redactVal = fmt.Sprintf("%s###%s", val[0:2], val[len(val)-2:])
	}
	s.logger.Debug("found secret", "key", envKey, "val", redactVal, "length", len(val))
}

func (s *secretManager) secretManagerGetter(params *pluginhooks.SesssionParams) (map[string]any, error) {
	keyid, _ := base64.StdEncoding.DecodeString(params.PluginEnvVars["AWS_ACCESS_KEY_ID"])
	skey, _ := base64.StdEncoding.DecodeString(params.PluginEnvVars["AWS_SECRET_ACCESS_KEY"])
	region, _ := base64.StdEncoding.DecodeString(params.PluginEnvVars["AWS_REGION"])
	var svc *secretsmanager.SecretsManager
	if keyid == nil || skey == nil || region == nil {
		return nil, fmt.Errorf("missing aws credentials")
	}
	svc, err := newAWSSecretsManagerClient(string(keyid), string(skey), string(region))
	if err != nil {
		return nil, err
	}

	secretKeyVal := map[string]map[string]string{}
	var responseConnEnvVar map[string]any
	for envKey, val := range params.ConnectionEnvVars {
		encVal, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("connection env value inconsistent type, envkey=%v, got=%T, want=string",
				envKey, val)
		}
		decVal, err := base64.StdEncoding.DecodeString(encVal)
		if err != nil {
			return nil, fmt.Errorf("failed decoding val, envkey=%v, err=%v", envKey, err)
		}
		if responseConnEnvVar == nil {
			responseConnEnvVar = map[string]any{}
		}
		attr, err := parseAWSConnectionVal(string(decVal))
		if err != nil {
			return nil, err
		}
		if attr.provider != "aws" {
			return nil, fmt.Errorf("provider '%s' not implement", attr.provider)
		}
		if keyVal, ok := secretKeyVal[attr.secretID]; ok {
			if val, ok := keyVal[attr.secretKey]; ok {
				s.logRedactVal(envKey, val)
				responseConnEnvVar[envKey] = base64.StdEncoding.EncodeToString([]byte(val))
				continue
			}
		}

		keyVal, err := getAWSSecretValue(svc, attr.secretID)
		if err != nil {
			return nil, fmt.Errorf("failed to get %s/%s, err=%v", envKey, decVal, err)
		}
		secretVal, ok := keyVal[attr.secretKey]
		if !ok {
			return nil, fmt.Errorf("key not found, secretid=%s, secretkey=%s, envkey=%s",
				attr.secretID, attr.secretKey, envKey)
		}
		secretKeyVal[attr.secretID] = keyVal
		s.logRedactVal(envKey, secretVal)
		responseConnEnvVar[envKey] = base64.StdEncoding.EncodeToString([]byte(secretVal))
	}
	return responseConnEnvVar, nil
}

func (s *secretManager) OnSessionOpen(params *pluginhooks.SesssionParams, resp *pluginhooks.SessionParamsResponse) error {
	s.logger.Info("opening session", "session", params.SessionID, "verb", params.ClientVerb)
	s.params = params
	connectionEnvVars, err := s.secretManagerGetter(params)
	if err != nil {
		return err
	}
	if connectionEnvVars == nil {
		s.logger.Info("empty connection envvars", "session", params.SessionID)
		return nil
	}

	resp.ConnectionEnvVars = connectionEnvVars
	return nil
}

func (s *secretManager) OnReceive(req *pluginhooks.Request, resp *pluginhooks.Response) error {
	s.logger.Debug("on-receive", "session", req.SessionID, "verb", s.params.ClientVerb)
	return nil
}

func (s *secretManager) OnSend(req *pluginhooks.Request, resp *pluginhooks.Response) error {
	s.logger.Debug("on-send", "session", req.SessionID)
	return nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Info,
		Output: os.Stderr,
	})
	logger.Debug("starting plugin secretmanager")
	pluginhooks.Serve(&secretManager{logger: logger})
}
