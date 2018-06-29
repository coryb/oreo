package oreo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	flock "github.com/theckman/go-flock"
	logging "gopkg.in/op/go-logging.v1"
)

type PreRequestCallback func(*http.Request) (*http.Request, error)
type PostRequestCallback func(*http.Request, *http.Response) (*http.Response, error)

type Logger interface {
	Debugf(format string, v ...interface{})
}

var DefaultLog Logger = logging.MustGetLogger("oreo")

// var CookieFile = filepath.Join(os.Getenv("HOME"), ".oreo-cookies.js")

var TraceRequestBody = false
var TraceResponseBody = false

type Client struct {
	pester.Client
	preCallbacks  []PreRequestCallback
	postCallbacks []PostRequestCallback

	cookieFile           string
	handlingPostCallback bool
	log                  Logger
}

func New() *Client {
	return &Client{
		Client:               *pester.New(),
		handlingPostCallback: false,
		preCallbacks:         []PreRequestCallback{},
		postCallbacks:        []PostRequestCallback{},
		log:                  DefaultLog,
	}
}

func (c *Client) WithLogger(log Logger) *Client {
	cp := *c
	cp.log = log
	return &cp
}

func (c *Client) WithCookieFile(file string) *Client {
	cp := *c
	cp.cookieFile = file
	if cp.Jar != nil {
		cp.Jar = nil
	}
	// need to reset cached http client with embedded jar
	cp.Client.EmbedHTTPClient(nil)
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
	// need to reset cached http client with embedded timeout
	cp.Client.EmbedHTTPClient(nil)
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
	// need to reset cached http client with embedded tranport
	cp.Client.EmbedHTTPClient(nil)
	return &cp
}

func (c *Client) WithPostCallback(callback PostRequestCallback) *Client {
	cp := *c
	cp.postCallbacks = append(cp.postCallbacks, callback)
	return &cp
}

func (c *Client) WithoutPostCallbacks() *Client {
	cp := *c
	cp.postCallbacks = []PostRequestCallback{}
	return &cp
}

func (c *Client) WithPreCallback(callback PreRequestCallback) *Client {
	cp := *c
	cp.preCallbacks = append(cp.preCallbacks, callback)
	return &cp
}

func (c *Client) WithoutPreCallbacks() *Client {
	cp := *c
	cp.preCallbacks = []PreRequestCallback{}
	return &cp
}

func NoRedirect(req *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) WithoutCallbacks() *Client {
	return c.WithoutPreCallbacks().WithoutPostCallbacks()
}

func (c *Client) WithCheckRedirect(checkFunc func(*http.Request, []*http.Request) error) *Client {
	cp := *c
	cp.CheckRedirect = checkFunc
	// need to reset cached http client with embedded CheckRedirect
	cp.Client.EmbedHTTPClient(nil)
	return &cp
}

func (c *Client) WithRedirect() *Client {
	return c.WithCheckRedirect(nil)
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
		url, err := url.Parse(fmt.Sprintf("http://%s", cookie.Domain))
		if err != nil {
			return err
		}
		c.Jar.SetCookies(url, []*http.Cookie{cookie})
	}
	return nil
}

type SaveCookieError struct {
	err error
}

func (e *SaveCookieError) Error() string {
	return fmt.Sprintf("Failed to save cookie file: %s", e.err)
}

func (c *Client) saveCookies(resp *http.Response) error {
	if c.cookieFile == "" {
		return nil
	}
	if _, ok := resp.Header["Set-Cookie"]; !ok {
		return nil
	}

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		// if it is host:port then we need to split off port
		parts := strings.Split(resp.Request.URL.Host, ":")
		host := parts[0]
		c.log.Debugf("Setting DOMAIN to %s for Cookie: %s", host, cookie)
		cookie.Domain = host
	}

	// expiry in one week from now
	expiry := time.Now().Add(24 * 7 * time.Hour)
	for _, cookie := range cookies {
		cookie.Expires = expiry
	}

	currentCookies, err := c.loadCookies()
	if err != nil {
		return &SaveCookieError{err}
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

	lockFile := fmt.Sprintf("%s.lock", c.cookieFile)
	lock := flock.NewFlock(lockFile)
	locked := false
	for i := 0; i < 10; i++ {
		locked, err = lock.TryLock()
		if err != nil {
			return &SaveCookieError{err}
		}
		if locked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !locked {
		return &SaveCookieError{fmt.Errorf("Failed to get lock for cookieFile within 100ms")}
	}
	defer func() {
		os.Remove(lockFile)
		lock.Unlock()
	}()

	err = os.MkdirAll(path.Dir(c.cookieFile), 0755)
	if err != nil {
		return &SaveCookieError{err}
	}
	fh, err := os.OpenFile(c.cookieFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fh.Close()
	if err != nil {
		return &SaveCookieError{fmt.Errorf("Failed to open %s: %s", c.cookieFile, err)}
	}
	enc := json.NewEncoder(fh)
	if err := enc.Encode(cookies); err != nil {
		return &SaveCookieError{err}
	}
	return nil
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
		c.log.Debugf("Failed to parse cookie file: %s", err)
	}

	if os.Getenv("LOG_TRACE") != "" {
		c.log.Debugf("Loading Cookies: %s", cookies)
	}
	return cookies, nil
}

func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	for _, cb := range c.preCallbacks {
		req, err = cb(req)
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
	var bodyCache []byte
	if len(c.postCallbacks) > 0 && !c.handlingPostCallback && req.Body != nil {
		bodyCache, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(bodyCache))
	}

	c.log.Debugf("%s %s", req.Method, req.URL.String())
	if TraceRequestBody {
		out, _ := httputil.DumpRequest(req, true)
		c.log.Debugf("Request: %s", out)
	}

	resp, err = c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	// log any cookies sent b/c they will not be present until
	// afater we call the `Do` func
	if TraceRequestBody {
		for key, values := range req.Header {
			if key == "Cookie" {
				for _, cookie := range values {
					c.log.Debugf("Cookie: %s", cookie)
				}
			}
		}
	}

	if TraceResponseBody {
		out, _ := httputil.DumpResponse(resp, true)
		c.log.Debugf("Response: %s", out)
	}

	err = c.saveCookies(resp)
	if err != nil {
		return resp, err
	}

	if len(c.postCallbacks) > 0 && !c.handlingPostCallback {
		if len(bodyCache) > 0 {
			req.Body = ioutil.NopCloser(bytes.NewReader(bodyCache))
		}
		c.handlingPostCallback = true
		defer func() {
			c.handlingPostCallback = false
		}()
		for _, cb := range c.postCallbacks {
			resp, err = cb(req, resp)
			if err != nil {
				return resp, err
			}
		}
	}

	return resp, err
}

func (c *Client) Get(ctx context.Context, urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("GET").Build()
	return c.Do(req)
}

func (c *Client) GetJSON(ctx context.Context, urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	contentType := "application/json"
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("GET").WithContentType(contentType).WithHeader("Accept", contentType).Build()
	return c.Do(req)
}

func (c *Client) GetXML(ctx context.Context, urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	contentType := "application/xml"
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("GET").WithContentType(contentType).WithHeader("Accept", contentType).Build()
	return c.Do(req)
}

func (c *Client) Head(ctx context.Context, urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("HEAD").Build()
	return c.Do(req)
}

func (c *Client) Post(ctx context.Context, urlStr string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("POST").WithContentType(bodyType).WithBody(body).Build()
	return c.Do(req)
}

func (c *Client) PostForm(ctx context.Context, urlStr string, data url.Values) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("POST").WithPostForm(data).Build()
	return c.Do(req)
}

func (c *Client) PostJSON(ctx context.Context, urlStr string, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("POST").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) PostXML(ctx context.Context, urlStr string, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("POST").WithXML(xmlStr).Build()
	return c.Do(req)
}

func (c *Client) Put(ctx context.Context, urlStr string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("PUT").WithContentType(bodyType).WithBody(body).Build()
	return c.Do(req)
}

func (c *Client) PutJSON(ctx context.Context, urlStr, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("PUT").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) PutXML(ctx context.Context, urlStr, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("PUT").WithXML(xmlStr).Build()
	return c.Do(req)
}

func (c *Client) Delete(ctx context.Context, urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("DELETE").Build()
	return c.Do(req)
}

func (c *Client) DeleteJSON(ctx context.Context, urlStr string, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("DELETE").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) DeleteXML(ctx context.Context, urlStr string, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithContext(ctx).WithMethod("DELETE").WithXML(xmlStr).Build()
	return c.Do(req)
}
