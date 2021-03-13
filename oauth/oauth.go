package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/sachin-ghait-cld/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic    = "X-Public"
	headerXClientID  = "X-Client-Id"
	headerXCallerID  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8091",
		Timeout: 100 * time.Millisecond,
	}
)

type oauthClient struct {
}

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthInterface interface{}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerID(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(req.Header.Get(headerXClientID), 10, 64)
	if err == nil {
		return 0
	}
	return clientID
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}
	cleanRequest(req)
	accesstoken := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accesstoken == "" {
		return nil
	}
	at, err := getAccessToken(accesstoken)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	req.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	req.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientID)
	req.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	resp := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if resp == nil || resp.Response == nil {
		return nil, errors.NewInternalServerError("Invalid response when trying to get user")
	}
	if resp.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(resp.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface")
		}
		return nil, &restErr
	}
	var token accessToken
	if err := json.Unmarshal(resp.Bytes(), &token); err != nil {
		return nil, errors.NewInternalServerError("invalid user interface")
	}
	return &token, nil
}
