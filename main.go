package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go/logging"
	"github.com/hashicorp/go-hclog"
	"github.com/hoophq/pluginhooks"
)

type secretManager struct {
	logger    hclog.Logger
	awsLogger *awsLogger
	params    *pluginhooks.SesssionParams
}

type secretProviderType string

const (
	// fetch secrets from aws secrets manager
	secretProviderAWSSecretsManager secretProviderType = "aws"
	// fetches secrets from environment variables mapped as json in unix environments
	secretProviderEnvJSON secretProviderType = "envjson"
)

type valAttr struct {
	smService *secretsmanager.Client
}

func newValAttr(pluginEnvVars map[string]string, wLogger io.Writer) (*valAttr, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	svc := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.ClientLogMode = aws.LogSigning | aws.LogRequest | aws.LogResponseWithBody
		o.Logger = logging.NewStandardLogger(wLogger)
	})
	return &valAttr{smService: svc}, nil
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
	s.logger.Debug("plugin env vars", "length", len(params.PluginEnvVars))
	for key, val := range params.PluginEnvVars {
		decVal, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("failed to decode plugin config key %v, err=%v", key, err)
		}
		s.logger.Debug("setting env", "key", key, "val-length", len(decVal))
		if err := os.Setenv(key, string(decVal)); err != nil {
			return nil, fmt.Errorf("failed configuring plugin config env %v, err=%v", key, err)
		}
	}
	attrInstance, err := newValAttr(params.PluginEnvVars, s.awsLogger)
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

type awsLogger struct {
	logger hclog.Logger
}

func (w *awsLogger) Write(b []byte) (int, error) {
	if w.logger != nil && b != nil {
		w.logger.Debug(string(b), "lib", "aws")
	}
	return 0, nil
}

func getAWSSecretValue(svc *secretsmanager.Client, secretID string) (map[string]string, error) {
	if svc == nil {
		return nil, fmt.Errorf("secret manager not configured")
	}
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}
	result, err := svc.GetSecretValue(context.Background(), input)
	if err != nil {
		return nil, err
	}
	var keyValSecret map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &keyValSecret); err != nil {
		return nil, fmt.Errorf("failed deserializing secret key/val")
	}
	return keyValSecret, nil
}

func main() {
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	hcLogLevel := hclog.Info
	switch logLevel {
	case "debug", "trace":
		hcLogLevel = hclog.Debug
	default:
		hcLogLevel = hclog.Info
	}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:             hcLogLevel,
		Output:            os.Stderr,
		DisableTime:       true,
		IndependentLevels: true,
		JSONFormat:        true,
	})
	awslogger := &awsLogger{logger: nil}
	if logLevel == "trace" {
		awslogger.logger = logger
	}
	logger.Info("starting plugin secretmanager", "awslogger", logLevel == "trace")
	pluginhooks.Serve(&secretManager{
		logger:    logger,
		awsLogger: awslogger,
	})
}
