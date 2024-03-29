package oreo

import (
	"bytes"
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

	flock "github.com/theckman/go-flock"
)

type Logger interface {
	Printf(format string, args ...interface{})
}

type nullLogger struct{}

func (n *nullLogger) Printf(format string, args ...interface{}) {}

var DefaultLogger Logger = &nullLogger{}

type PreRequestCallback func(*http.Request) (*http.Request, error)
type PostRequestCallback func(*http.Request, *http.Response) (*http.Response, error)

type Client struct {
	http.Client
	backoff    BackoffStrategy
	maxRetries int

	preCallbacks  []PreRequestCallback
	postCallbacks []PostRequestCallback

	cookieFile           string
	handlingPostCallback bool
	log                  Logger
	traceCookies         bool
	traceRequestBody     bool
	traceResponseBody    bool
}

func New() *Client {
	return &Client{
		maxRetries:           3,
		handlingPostCallback: false,
		preCallbacks:         []PreRequestCallback{},
		postCallbacks:        []PostRequestCallback{},
		log:                  DefaultLogger,
	}
}

func (c *Client) WithCookieFile(file string) *Client {
	cp := *c
	cp.cookieFile = file
	if cp.Jar != nil {
		cp.Jar = nil
	}
	return &cp
}

func (c *Client) WithRetries(retries int) *Client {
	cp := *c
	// pester MaxRetries is really a MaxAttempts, so if you
	// want 2 retries that means 3 attempts
	cp.maxRetries = retries + 1
	return &cp
}

func (c *Client) WithTimeout(duration time.Duration) *Client {
	cp := *c
	cp.Timeout = duration
	return &cp
}

type BackoffStrategy int

const (
	CONSTANT_BACKOFF BackoffStrategy = iota
	LINEAR_BACKOFF   BackoffStrategy = iota
	NO_BACKOFF       BackoffStrategy = iota
)

func (c *Client) WithBackoff(backoff BackoffStrategy) *Client {
	cp := *c
	cp.backoff = backoff
	return &cp
}

func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	cp := *c
	cp.Transport = transport
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
	return &cp
}

func (c *Client) WithoutRedirect() *Client {
	return c.WithCheckRedirect(NoRedirect)
}

func (c *Client) WithLogger(l Logger) *Client {
	cp := *c
	cp.log = l
	return &cp
}

func (c *Client) WithRequestTrace(b bool) *Client {
	cp := *c
	cp.traceRequestBody = b
	return &cp
}

func (c *Client) WithResponseTrace(b bool) *Client {
	cp := *c
	cp.traceResponseBody = b
	return &cp
}

func (c *Client) WithTrace(b bool) *Client {
	cp := *c
	cp.traceRequestBody = b
	cp.traceResponseBody = b
	cp.traceCookies = b
	return &cp
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
		// this is dumb, cookie.Domain *must not* have a scheme or port url.Parse will parse strings like "localhost"
		// into the Path variable, not Host.  So lets just force Host. We also need to set arbitrary http/https Scheme
		// as Jar.SetCookies will ignore cookies where the url does not have a http/https Scheme
		u := &url.URL{
			Scheme: "http",
			Host:   cookie.Domain,
		}
		c.Jar.SetCookies(u, []*http.Cookie{cookie})
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
		if cookie.Domain == "" {
			// if it is host:port then we need to split off port
			parts := strings.Split(resp.Request.URL.Host, ":")
			host := parts[0]
			c.log.Printf("Setting DOMAIN to %s for Cookie: %s", host, cookie)
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
		c.log.Printf("Failed to parse cookie file: %s", err)
	}

	if c.traceCookies {
		c.log.Printf("Loading Cookies: %s", cookies)
	}
	return cookies, nil
}

type bytesReaderCloser struct {
	bytes.Reader
}

func (b *bytesReaderCloser) Close() error {
	return nil
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
	if (c.maxRetries != 0 || (c.traceRequestBody || len(c.postCallbacks) > 0)) && req.Body != nil {
		bites, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		reader := bytes.NewReader(bites)
		req.Body = &bytesReaderCloser{*reader}
	}

	attempt := 1
	for {
		resp, err = c.Client.Do(req)
		if err != nil {
			if c.traceRequestBody {
				rewindRequest(req)
				out, _ := httputil.DumpRequestOut(req, true)
				c.log.Printf("Request %d: %s", attempt, out)
			}
		} else {
			// we log this after the request is made because http.send
			// will modify the request to append cookies, so to see the
			// cookies sent we need to log post-send.
			if c.traceRequestBody {
				rewindRequest(req)
				out, _ := httputil.DumpRequestOut(req, true)
				c.log.Printf("Request %d: %s", attempt, out)
			}

			if c.traceResponseBody {
				out, _ := httputil.DumpResponse(resp, true)
				c.log.Printf("Response %d: %s", attempt, out)
			}
		}

		if err != nil || resp.StatusCode >= 500 {
			if c.maxRetries < 0 || c.maxRetries < attempt+1 {
				break
			}

			var idle time.Duration
			if c.backoff == CONSTANT_BACKOFF {
				idle = time.Duration(1 * time.Second)
			} else if c.backoff == LINEAR_BACKOFF {
				idle = time.Duration(attempt) * time.Second
			}

			if err != nil {
				c.log.Printf("Attempt %d error: %s, retry in %s", attempt, err, idle)
			} else {
				c.log.Printf("Attempt %d failed: %s, retry in %s", attempt, resp.Status, idle)
			}

			select {
			case <-req.Context().Done():
				c.log.Printf("Request Context timeout after attempt %d", attempt)
				return
			case <-time.After(idle):
			}

			// need to reset body for the retry
			rewindRequest(req)

			attempt++
			continue
		}
		break
	}

	if err != nil {
		return nil, err
	}

	err = c.saveCookies(resp)
	if err != nil {
		return resp, err
	}

	if len(c.postCallbacks) > 0 && !c.handlingPostCallback {
		rewindRequest(req)
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

func rewindRequest(req *http.Request) {
	if req.Body != nil {
		if rs, ok := req.Body.(io.ReadSeeker); ok {
			rs.Seek(0, 0)
		}
	}
}

func (c *Client) Get(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("GET").Build()
	return c.Do(req)
}

func (c *Client) GetJSON(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	contentType := "application/json"
	req := RequestBuilder(parsed).WithMethod("GET").WithContentType(contentType).WithHeader("Accept", contentType).Build()
	return c.Do(req)
}

func (c *Client) GetXML(urlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	contentType := "application/xml"
	req := RequestBuilder(parsed).WithMethod("GET").WithContentType(contentType).WithHeader("Accept", contentType).Build()
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

func (c *Client) Patch(urlStr string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	req := RequestBuilder(parsed).WithMethod("PATCH").WithContentType(bodyType).WithBody(body).Build()
	return c.Do(req)
}

func (c *Client) PatchJSON(urlStr string, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	req := RequestBuilder(parsed).WithMethod("PATCH").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) PatchXML(urlStr string, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	req := RequestBuilder(parsed).WithMethod("PATCH").WithXML(xmlStr).Build()
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

func (c *Client) PostXML(urlStr string, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("POST").WithXML(xmlStr).Build()
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

func (c *Client) PutXML(urlStr, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("PUT").WithXML(xmlStr).Build()
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

func (c *Client) DeleteJSON(urlStr string, jsonStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("DELETE").WithJSON(jsonStr).Build()
	return c.Do(req)
}

func (c *Client) DeleteXML(urlStr string, xmlStr string) (resp *http.Response, err error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	req := RequestBuilder(parsed).WithMethod("DELETE").WithXML(xmlStr).Build()
	return c.Do(req)
}
