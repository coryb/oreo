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
	"path/filepath"
	"strings"
	"time"

	logging "github.com/op/go-logging"
	"github.com/sethgrid/pester"
)

var log = logging.MustGetLogger("oreo")
var CookieFile = filepath.Join(os.Getenv("HOME"), ".oreo-cookies.js")

type Client struct {
	pester.Client
	CookieFile   string
	AfterRequest func(*http.Request, *http.Response) (*http.Response, error)

	handlingAfterRequest bool
}

func New() *Client {
	return &Client{
		Client:               *pester.New(),
		CookieFile:           CookieFile,
		handlingAfterRequest: false,
	}
}

func NewExtendedClient(hc *http.Client) *Client {
	return &Client{
		Client:               *pester.NewExtendedClient(hc),
		CookieFile:           CookieFile,
		handlingAfterRequest: false,
	}
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

	err = os.MkdirAll(path.Dir(c.CookieFile), 0755)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(c.CookieFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fh.Close()
	if err != nil {
		log.Errorf("Failed to open %s: %s", c.CookieFile, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(fh)
	return enc.Encode(cookies)
}

func (c *Client) loadCookies() ([]*http.Cookie, error) {
	bytes, err := ioutil.ReadFile(CookieFile)
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

func (c *Client) Get(url string) (*http.Response, error) {
	return c.makeRequestWithoutContent("GET", url)
}

func (c *Client) Head(url string) (*http.Response, error) {
	return c.makeRequestWithoutContent("HEAD", url)
}

func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.makeRequestWithContent("POST", url, contentType, body)
}

func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.makeRequestWithContent("POST", url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (c *Client) Put(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.makeRequestWithContent("PUT", url, contentType, body)
}

func (c *Client) Delete(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.makeRequestWithContent("DELETE", url, contentType, body)
}

type nopSeeker struct {
	io.Reader
}

func (nopSeeker) Seek(int64, int) (int64, error) {
	return 0, nil
}

func (c *Client) makeRequestWithContent(method, url, contentType string, body io.Reader) (resp *http.Response, err error) {
	var content io.ReadSeeker = nopSeeker{body}

	// AfterRequest may want to resubmit the request, so we
	// will need to rewind (Seek) the Reader back to start.
	if c.AfterRequest != nil && !c.handlingAfterRequest {
		bites, err := ioutil.ReadAll(body)
		if err != nil {
			return nil, err
		}
		content = bytes.NewReader(bites)
	}
	req, err := http.NewRequest(method, url, content)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	log.Debugf("%s %s", req.Method, req.URL.String())
	if resp, err = c.makeRequest(req); err != nil {
		return nil, err
	}
	if c.AfterRequest != nil && !c.handlingAfterRequest {
		content.Seek(0, 0)
		c.handlingAfterRequest = true
		defer func() {
			c.handlingAfterRequest = false
		}()
		return c.AfterRequest(req, resp)
	}
	return resp, err
}

func (c *Client) makeRequestWithoutContent(method, uri string) (resp *http.Response, err error) {
	req, err := http.NewRequest(method, uri, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("%s %s", req.Method, req.URL.String())
	if resp, err = c.makeRequest(req); err != nil {
		return nil, err
	}
	if c.AfterRequest != nil && !c.handlingAfterRequest {
		c.handlingAfterRequest = true
		defer func() {
			c.handlingAfterRequest = false
		}()
		return c.AfterRequest(req, resp)
	}
	return resp, err
}

func (c *Client) makeRequest(req *http.Request) (resp *http.Response, err error) {
	req.Header.Set("Accept", "application/json")

	if log.IsEnabledFor(logging.DEBUG) {
		// this is actually done in http.send but doing it
		// here so we can log it in DumpRequest for debugging
		for _, cookie := range c.Client.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}

		out, _ := httputil.DumpRequest(req, true)
		log.Debugf("Request: %s", out)
	}

	if resp, err = c.Client.Do(req); err != nil {
		log.Errorf("Failed to %s %s: %s", req.Method, req.URL.String(), err)
		return nil, err
	}

	if _, ok := resp.Header["Set-Cookie"]; ok {
		c.saveCookies(resp)
	}
	if log.IsEnabledFor(logging.DEBUG) {
		out, _ := httputil.DumpResponse(resp, true)
		log.Debugf("Response: %s", out)
	}
	return resp, nil
}
