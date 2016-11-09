package azureopenid

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

// KeyResponse holds the response from Azure
type KeyResponse struct {
	Keys []struct {
		E   string `json:"e"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		Use string `json:"use"`
	} `json:"keys"`
}

// AzureApp holds our Azure goodies
type AzureApp struct {
	TenantName    string
	ClientID      string
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSEndpoint  string `json:"jwks_uri"`
}

// New creates an AzureApp instance
func New(tenant, clientid string) (AzureApp, error) {
	azureApp := AzureApp{TenantName: tenant, ClientID: clientid}
	res, err := http.Get("https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration")
	if err != nil {
		log.Println("error GETing openid endpoint: ", err)
		return azureApp, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("err reading body: ", err)
		return azureApp, err
	}
	err = json.Unmarshal(body, &azureApp)
	if err != nil {
		log.Println("json error: ", err)
		return azureApp, err
	}

	return azureApp, err
}

// loadKids gathers keys from Azure JWKS endpoint
func (a *AzureApp) loadKids(policy string) (KeyResponse, error) {
	var kidsResp KeyResponse
	res, err := http.Get(a.JWKSEndpoint + "?p=" + policy)
	if err != nil {
		log.Println("error loading kids: ", err)
		return kidsResp, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("err reading body: ", err)
		return kidsResp, err
	}
	err = json.Unmarshal(body, &kidsResp)
	if err != nil {
		log.Println("json error: ", err)
		return kidsResp, err
	}
	return kidsResp, nil
}

// ParseToken parses out a JWT token
func (a *AzureApp) ParseToken(idtoken, policy string) (*jwt.Token, error) {
	kids, err := a.loadKids(policy)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(idtoken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		for _, v := range kids.Keys {
			if token.Header["kid"] == v.Kid {

				decodedE, err := base64.RawURLEncoding.DecodeString(v.E)
				if err != nil {
					return nil, err
				}
				if len(decodedE) < 4 {
					ndata := make([]byte, 4)
					copy(ndata[4-len(decodedE):], decodedE)
					decodedE = ndata
				}
				pubKey := &rsa.PublicKey{
					N: &big.Int{},
					E: int(binary.BigEndian.Uint32(decodedE[:])),
				}
				decodedN, err := base64.RawURLEncoding.DecodeString(v.N)
				if err != nil {
					return nil, err
				}

				pubKey.N.SetBytes(decodedN)
				return pubKey, nil
			}
		}
		return nil, fmt.Errorf("no matching key found")
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

// ValidToken returns if the provided token is valid or not
func (a *AzureApp) ValidToken(token *jwt.Token, nonce string) bool {
	claims := token.Claims.(jwt.MapClaims)
	if nonce == "" {
		if token.Valid {
			return true
		}
	} else {
		if token.Valid && claims["nonce"] == nonce {
			return true
		}
	}
	return false
}
