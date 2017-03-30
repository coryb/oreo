package oreo

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sethgrid/pester"
	logging "gopkg.in/op/go-logging.v1"
)

type PreRequestCallback func(*http.Request) (*http.Request, error)
type PostRequestCallback func(*http.Request, *http.Response) (*http.Response, error)

var log = logging.MustGetLogger("oreo")

// var CookieFile = filepath.Join(os.Getenv("HOME"), ".oreo-cookies.js")

var TraceRequestBody = false
var TraceResponseBody = false

type Client struct {
	pester.Client
	preCallback  PreRequestCallback
	postCallback PostRequestCallback

	cookieFile           string
	handlingPostCallback bool
}

func New() *Client {
	return &Client{
		Client:               *pester.New(),
		handlingPostCallback: false,
	}
}

func (c *Client) WithCookieFile(file string) *Client {
	cp := *c
	cp.cookieFile = file
	return &cp
}

func (c *Client) WithRetries(retries int) *Client {
	cp := *c
	// pester MaxRetries is really a MaxAttempts, so if you
	// want 2 retries that means 3 attempts
	cp.MaxRetries = retries + 1
	return &cp
}

func (c *Client) WithTimeout(duration time.Duration) *Client {
	cp := *c
	cp.Timeout = duration
	return &cp
}

type BackoffStrategy int

const (
	CONSTANT_BACKOFF           BackoffStrategy = iota
	EXPONENTIAL_BACKOFF        BackoffStrategy = iota
	EXPONENTIAL_JITTER_BACKOFF BackoffStrategy = iota
	LINEAR_BACKOFF             BackoffStrategy = iota
	LINEAR_JITTER_BACKOFF      BackoffStrategy = iota
)

func (c *Client) WithBackoff(backoff BackoffStrategy) *Client {
	cp := *c
	switch backoff {
	case CONSTANT_BACKOFF:
		cp.Backoff = pester.DefaultBackoff
	case EXPONENTIAL_BACKOFF:
		cp.Backoff = pester.ExponentialBackoff
	case EXPONENTIAL_JITTER_BACKOFF:
		cp.Backoff = pester.ExponentialJitterBackoff
	case LINEAR_BACKOFF:
		cp.Backoff = pester.LinearBackoff
	case LINEAR_JITTER_BACKOFF:
		cp.Backoff = pester.LinearJitterBackoff
	}
	return &cp
}

func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	cp := *c
	cp.Transport = transport
	return &cp
}

func (c *Client) WithPostCallback(callback PostRequestCallback) *Client {
	cp := *c
	cp.postCallback = callback
	return &cp
}

func (c *Client) WithPreCallback(callback PreRequestCallback) *Client {
	cp := *c
	cp.preCallback = callback
	return &cp
}

func NoRedirect(req *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) WithCheckRedirect(checkFunc func(*http.Request, []*http.Request) error) *Client {
	cp := *c
	cp.CheckRedirect = checkFunc
	return &cp
}

func (c *Client) WithoutRedirect() *Client {
	return c.WithCheckRedirect(NoRedirect)
}

func (c *Client) initCookieJar() (err error) {
	if c.Jar != nil {
		return nil
	}
	c.Jar, err = cookiejar.New(nil)
	if err != nil {
		return err
	}

	cookies, err := c.loadCookies()
	if err != nil {
		return err
	}
	for _, cookie := range cookies {
		url, err := url.Parse(cookie.Domain)
		if err != nil {
			return err
		}
		c.Jar.SetCookies(url, []*http.Cookie{cookie})
	}
	return nil
}

func (c *Client) saveCookies(resp *http.Response) error {
	if _, ok := resp.Header["Set-Cookie"]; !ok {
		return nil
	}

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Domain == "" {
			// if it is host:port then we need to split off port
			parts := strings.Split(resp.Request.URL.Host, ":")
			host := parts[0]
			log.Debugf("Setting DOMAIN to %s for Cookie: %s", host, cookie)
			cookie.Domain = host
		}
	}

	// expiry in one week from now
	expiry := time.Now().Add(24 * 7 * time.Hour)
	for _, cookie := range cookies {
		cookie.Expires = expiry
	}

	currentCookies, err := c.loadCookies()
	if err != nil {
		return err
	}
	if currentCookies != nil {
		currentCookiesByName := make(map[string]*http.Cookie)
		for _, cookie := range currentCookies {
			currentCookiesByName[cookie.Name+cookie.Domain] = cookie
		}

		for _, cookie := range cookies {
			currentCookiesByName[cookie.Name+cookie.Domain] = cookie
		}

		mergedCookies := make([]*http.Cookie, 0, len(currentCookiesByName))
		for _, v := range currentCookiesByName {
			mergedCookies = append(mergedCookies, v)
		}
		cookies = mergedCookies
	}

	err = os.MkdirAll(path.Dir(c.cookieFile), 0755)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(c.cookieFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fh.Close()
	if err != nil {
		log.Errorf("Failed to open %s: %s", c.cookieFile, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(fh)
	return enc.Encode(cookies)
}

func (c *Client) loadCookies() ([]*http.Cookie, error) {
	bytes, err := ioutil.ReadFile(c.cookieFile)
	if err != nil && os.IsNotExist(err) {
		// dont load cookies if the file does not exist
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cookies := []*http.Cookie{}
	err = json.Unmarshal(bytes, &cookies)
	if err != nil {
		return nil, err
	}

	if log.IsEnabledFor(logging.DEBUG) && os.Getenv("LOG_TRACE") != "" {
		log.Debugf("Loading Cookies: %s", cookies)
	}
	return cookies, nil
}

func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	if c.preCallback != nil {
		req, err = c.preCallback(req)
		if err != nil {
			return nil, err
		}
	}

	err = c.initCookieJar()
	if err != nil {
		return nil, err
	}

	// Callback may want to resubmit the request, so we
	// will need to rewind (Seek) the Reader back to start.
	if c.postCallback != nil && !c.handlingPostCallback && req.Body != nil {
		bites, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(bites))
	}

	log.Debugf("%s %s", req.Method, req.URL.String())
	resp, err = c.Client.Do(req)
	if err != nil {
		if log.IsEnabledFor(logging.DEBUG) && TraceRequestBody {
			out, _ := httputil.DumpRequest(req, true)
			log.Debugf("Request: %s", out)
		}

		return nil, err
	}

	err = c.saveCookies(resp)
	if err != nil {
		return nil, err
	}

	// we log this after the request is made because http.send
	// will modify the request to append cookies, so to see the
	// cookies sent we need to log post-send.
	if log.IsEnabledFor(logging.DEBUG) && TraceRequestBody {
		out, _ := httputil.DumpRequest(req, true)
		log.Debugf("Request: %s", out)
	}

	if log.IsEnabledFor(logging.DEBUG) && TraceResponseBody {
		out, _ := httputil.DumpResponse(resp, true)
		log.Debugf("Response: %s", out)
	}

	if c.postCallback != nil && !c.handlingPostCallback {
		if req.Body != nil {
			rs, ok := req.Body.(io.ReadSeeker)
			if ok {
				rs.Seek(0, 0)
			}
		}
		c.handlingPostCallback = true
		defer func() {
			c.handlingPostCallback = false
		}()
		return c.postCallback(req, resp)
	}

	return resp, err
}

func (c *Client) Get(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("GET").Build()
	return c.Do(req)
}

func (c *Client) Head(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("HEAD").Build()
	return c.Do(req)
}

func (c *Client) Post(urlStr string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("POST").WithContentType(bodyType).WithBody(body).Build()
	return c.Do(req)
}

func (c *Client) PostForm(urlStr string, data url.Values) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("POST").WithPostForm(data).Build()
	return c.Do(req)
}

func (c *Client) PostJSON(urlStr string, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("POST").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) Put(urlStr string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("PUT").WithContentType(bodyType).WithBody(body).Build()
	return c.Do(req)
}

func (c *Client) PutJSON(urlStr, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("PUT").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) Delete(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("DELETE").Build()
	return c.Do(req)
}
