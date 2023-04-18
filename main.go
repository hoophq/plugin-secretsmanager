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
	if svc == nil {
		return nil, fmt.Errorf("secret manager not configured")
	}
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
	if accessKeyID == "" || secretKey == "" || region == "" {
		return nil, nil
	}
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretKey, ""),
	})
	if err != nil {
		return nil, err
	}
	return secretsmanager.New(sess), nil
}

type secretProviderType string

const (
	// fetch secrets from aws secrets manager
	secretProviderAWSSecretsManager secretProviderType = "aws"
	// fetches secrets from environment variables mapped as json in unix environments
	secretProviderEnvJSON secretProviderType = "envjson"
)

type valAttr struct {
	smService *secretsmanager.SecretsManager
}

func newValAttr(pluginEnvVars map[string]string) (*valAttr, error) {
	if len(pluginEnvVars) > 0 {
		keyid, _ := base64.StdEncoding.DecodeString(pluginEnvVars["AWS_ACCESS_KEY_ID"])
		skey, _ := base64.StdEncoding.DecodeString(pluginEnvVars["AWS_SECRET_ACCESS_KEY"])
		region, _ := base64.StdEncoding.DecodeString(pluginEnvVars["AWS_REGION"])
		svc, err := newAWSSecretsManagerClient(string(keyid), string(skey), string(region))
		if err != nil {
			return nil, err
		}
		return &valAttr{smService: svc}, nil
	}
	return &valAttr{}, nil
}

// <provider>:<secret-id>:<secret-key>
func (a *valAttr) parseConnectionVal(val string) (string, error) {
	parts := strings.Split(val, ":")
	if len(parts) != 3 {
		return "", nil
	}
	secretProvider, secretID, secretKey := secretProviderType(parts[0]), parts[1], parts[2]
	switch secretProvider {
	case secretProviderAWSSecretsManager:
		if a.smService == nil {
			return "", fmt.Errorf("secret manager is missing required aws credentials")
		}
		keyVal, err := getAWSSecretValue(a.smService, secretID)
		if err != nil {
			return "", fmt.Errorf("failed to get %s/%s, err=%v", secretID, secretKey, err)
		}
		secretVal, ok := keyVal[secretKey]
		if !ok {
			return "", fmt.Errorf("key not found, secretid=%s, secretkey=%s",
				secretID, secretKey)
		}
		return string(secretVal), nil
	case secretProviderEnvJSON:
		envJson := os.Getenv(secretID)
		if envJson == "" {
			return "", fmt.Errorf("env not found for secret id %q", secretID)
		}
		var envMap map[string]string
		if err := json.Unmarshal([]byte(envJson), &envMap); err != nil {
			return "", fmt.Errorf("failed decoding secret id %q to json, err=%v", secretID, err)
		}
		val, ok := envMap[secretKey]
		if !ok {
			return "", fmt.Errorf("secret key %q not found in secret id %q", secretKey, secretID)
		}
		return val, nil
	}
	return "", fmt.Errorf("secret provider %q not implemented", secretProvider)
}

func (s *secretManager) logRedactVal(envKey string, val string) {
	redactVal := "#######"
	if len(val) > 8 {
		redactVal = fmt.Sprintf("%s###%s", val[0:2], val[len(val)-2:])
	}
	s.logger.Debug("found secret", "key", envKey, "val", redactVal, "length", len(val))
}

func (s *secretManager) secretManagerGetter(params *pluginhooks.SesssionParams) (map[string]any, error) {
	attrInstance, err := newValAttr(params.PluginEnvVars)
	if err != nil {
		return nil, err
	}
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
		secretVal, err := attrInstance.parseConnectionVal(string(decVal))
		if err != nil {
			return nil, err
		}
		if secretVal == "" {
			s.logger.Debug("bypassing", "key", envKey)
			continue
		}
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
	logLevel := "info"
	if strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		logLevel = "debug"
	}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:             hclog.LevelFromString(logLevel),
		Output:            os.Stderr,
		DisableTime:       true,
		IndependentLevels: true,
	})
	logger.Info("starting plugin secretmanager")
	pluginhooks.Serve(&secretManager{logger: logger})
}
