package pkg

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/airdb/ja3transport"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	destinationUrlHttps = "https://localhost:8444"
	destinationUrlHttp  = "http://localhost:8080"
	requestTimeout      = "5s"
)

func init() {
	if dst, exists := os.LookupEnv("TESTS_DESTINATION_URL_HTTPS"); exists {
		destinationUrlHttps = dst
	}
	if dst, exists := os.LookupEnv("TESTS_DESTINATION_URL_HTTP"); exists {
		destinationUrlHttp = dst
	}
	if timeout, exists := os.LookupEnv("TESTS_REQUEST_TIMEOUT"); exists {
		requestTimeout = timeout
	}

}

type NginxResponse struct {
	Ua      string `json:"ua"`
	Ja3     string `json:"ja3"`
	Ja3Hash string `json:"ja3_hash"`
	Greased string `json:"greased"`
}

func Test_browsersWithHttps(t *testing.T) {
	timeout, err := time.ParseDuration(requestTimeout)
	if err != nil {
		t.Fatalf("cant parse TESTS_REQUEST_TIMEOUT ('%s'): %s", requestTimeout, err.Error())
	}
	tests := []struct {
		browser ja3transport.Browser
		greased string
	}{
		{
			browser: ja3transport.ChromeVersion103,
			greased: "0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.browser.UserAgent, func(t *testing.T) {
			client, err := ja3transport.New(tt.browser)
			if !assert.NoError(t, err) {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			request, err := http.NewRequestWithContext(ctx, "GET", destinationUrlHttps, nil)
			if !assert.NoError(t, err) {
				return
			}

			response, err := client.Do(request)
			if !assert.NoError(t, err) {
				return
			}
			defer response.Body.Close()
			assert.Equal(t, http.StatusOK, response.StatusCode)

			nginxResponse := NginxResponse{}

			err = json.NewDecoder(response.Body).Decode(&nginxResponse)
			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, tt.browser.JA3, nginxResponse.Ja3)
			assert.Equal(t, fmt.Sprintf("%x", md5.Sum([]byte(tt.browser.JA3))), nginxResponse.Ja3Hash)
			assert.Equal(t, tt.greased, nginxResponse.Greased)
		})
	}
}

func Test_plainHttp(t *testing.T) {
	timeout, err := time.ParseDuration(requestTimeout)
	if err != nil {
		t.Fatalf("cant parse TESTS_REQUEST_TIMEOUT ('%s'): %s", requestTimeout, err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, "GET", destinationUrlHttp, nil)
	if !assert.NoError(t, err) {
		return
	}

	response, err := http.DefaultClient.Do(request)
	if !assert.NoError(t, err) {
		return
	}
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)

	nginxResponse := NginxResponse{}

	err = json.NewDecoder(response.Body).Decode(&nginxResponse)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "", nginxResponse.Ja3)
}
