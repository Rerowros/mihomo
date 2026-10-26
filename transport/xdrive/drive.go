package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	flatSeparator = "~"

	driveBoundary    = "xdrive-boundary"
	drivePageSize    = 1000
	driveMaxAttempts = 8
	driveMaxInflight = 32
	driveInlineLimit = 12000
	driveMaxBackoff  = 8 * time.Second
	driveTokenURL    = "https://oauth2.googleapis.com/token"
	driveFilesURL    = "https://www.googleapis.com/drive/v3/files"
	driveUploadURL   = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name"
	driveInitBackoff = 200 * time.Millisecond
)

// driveStorage keeps the segments in one Google Drive folder. A small object
// travels in the file description (one metadata request); a larger one uses a
// multipart upload. Names are flattened with "~" because Drive has no
// directories.
type driveStorage struct {
	folder       string
	clientID     string
	clientSecret string
	refreshToken string
	client       *http.Client
	inflight     chan struct{}

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time

	idMu sync.Mutex
	ids  map[string]string
}

func newDriveStorage(config *Config) (*driveStorage, error) {
	if config.RemoteFolder == "" {
		return nil, fmt.Errorf(`xdrive: empty "remote-folder", it must be a Google Drive folder id`)
	}
	if len(config.Secrets) != 3 {
		return nil, fmt.Errorf("xdrive: Google Drive needs 3 secrets in order of client-id, client-secret, refresh-token")
	}
	for i, secret := range config.Secrets {
		if secret == "" {
			return nil, fmt.Errorf("xdrive: Google Drive secret %d is empty", i)
		}
	}
	return &driveStorage{
		folder:       config.RemoteFolder,
		clientID:     config.Secrets[0],
		clientSecret: config.Secrets[1],
		refreshToken: config.Secrets[2],
		client:       newServiceClient(driveMaxInflight),
		inflight:     make(chan struct{}, driveMaxInflight),
		ids:          make(map[string]string),
	}, nil
}

func flatten(name string) string {
	return strings.ReplaceAll(name, "/", flatSeparator)
}

func quoteDriveValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
}

func (s *driveStorage) accessToken(ctx context.Context) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()

	if s.token != "" && time.Now().Before(s.tokenExpiry) {
		return s.token, nil
	}

	form := url.Values{
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"refresh_token": {s.refreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, driveTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("xdrive: build the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("xdrive: refresh the access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("xdrive: read the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("xdrive: the token endpoint answered %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("xdrive: parse the token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("xdrive: the token endpoint returned no access token")
	}

	lifetime := parsed.ExpiresIn
	if lifetime > 60 {
		lifetime -= 60
	}
	s.token = parsed.AccessToken
	s.tokenExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
	return s.token, nil
}

func jitter(backoff time.Duration) time.Duration {
	half := backoff / 2
	if half <= 0 {
		return backoff
	}
	return half + time.Duration(rand.Int63n(int64(half)))
}

func rateLimited(payload []byte) bool {
	var parsed struct {
		Error struct {
			Status string `json:"status"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &parsed) != nil {
		return false
	}
	for _, item := range parsed.Error.Errors {
		switch item.Reason {
		case "rateLimitExceeded", "userRateLimitExceeded", "sharingRateLimitExceeded":
			return true
		}
	}
	return parsed.Error.Status == "RESOURCE_EXHAUSTED"
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (s *driveStorage) do(ctx context.Context, method, target, contentType string, body []byte) (int, []byte, error) {
	backoff := driveInitBackoff
	var lastErr error

	for attempt := 0; attempt < driveMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(jitter(backoff)):
			}
			backoff *= 2
			if backoff > driveMaxBackoff {
				backoff = driveMaxBackoff
			}
		}

		token, err := s.accessToken(ctx)
		if err != nil {
			lastErr = err
			continue
		}

		select {
		case s.inflight <- struct{}{}:
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			<-s.inflight
			return 0, nil, fmt.Errorf("xdrive: build a Drive request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := s.client.Do(req)
		<-s.inflight
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = fmt.Errorf("xdrive: Drive request failed: %w", err)
			continue
		}
		payload, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = fmt.Errorf("xdrive: read the Drive response: %w", readErr)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			s.invalidateToken()
			lastErr = fmt.Errorf("xdrive: Drive rejected the access token")
			continue
		}
		if resp.StatusCode == http.StatusForbidden && rateLimited(payload) {
			lastErr = fmt.Errorf("xdrive: Drive is rate limiting: %s", payload)
			continue
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("xdrive: Drive answered %d: %s", resp.StatusCode, payload)
			continue
		}
		return resp.StatusCode, payload, nil
	}

	return 0, nil, lastErr
}

func (s *driveStorage) invalidateToken() {
	s.tokenMu.Lock()
	s.token = ""
	s.tokenMu.Unlock()
}

func (s *driveStorage) rememberID(name, id string) {
	s.idMu.Lock()
	s.ids[name] = id
	s.idMu.Unlock()
}

func (s *driveStorage) forgetID(name string) {
	s.idMu.Lock()
	delete(s.ids, name)
	s.idMu.Unlock()
}

func (s *driveStorage) cachedID(name string) (string, bool) {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	id, ok := s.ids[name]
	return id, ok
}

type driveFile struct {
	id          string
	description string
}

func (s *driveStorage) query(ctx context.Context, condition string) (map[string]driveFile, error) {
	found := make(map[string]driveFile)
	pageToken := ""

	for {
		params := url.Values{
			"q":                         {"'" + quoteDriveValue(s.folder) + "' in parents and trashed = false and " + condition},
			"fields":                    {"nextPageToken,files(id,name,description)"},
			"pageSize":                  {fmt.Sprint(drivePageSize)},
			"supportsAllDrives":         {"true"},
			"includeItemsFromAllDrives": {"true"},
		}
		if pageToken != "" {
			params.Set("pageToken", pageToken)
		}

		status, payload, err := s.do(ctx, http.MethodGet, driveFilesURL+"?"+params.Encode(), "", nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("xdrive: Drive listing answered %d: %s", status, payload)
		}

		var parsed struct {
			NextPageToken string `json:"nextPageToken"`
			Files         []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"files"`
		}
		if err := json.Unmarshal(payload, &parsed); err != nil {
			return nil, fmt.Errorf("xdrive: parse the Drive listing: %w", err)
		}

		for _, file := range parsed.Files {
			found[file.Name] = driveFile{id: file.ID, description: file.Description}
			s.rememberID(file.Name, file.ID)
		}

		pageToken = parsed.NextPageToken
		if pageToken == "" {
			return found, nil
		}
	}
}

func (s *driveStorage) resolveID(ctx context.Context, flat string) (string, error) {
	if id, ok := s.cachedID(flat); ok {
		return id, nil
	}
	found, err := s.query(ctx, "name = '"+quoteDriveValue(flat)+"'")
	if err != nil {
		return "", err
	}
	if file, ok := found[flat]; ok {
		return file.id, nil
	}
	return "", errNotFound
}

func (s *driveStorage) Put(ctx context.Context, name string, data []byte) error {
	if len(data) <= driveInlineLimit {
		return s.putInline(ctx, name, data)
	}
	return s.putMedia(ctx, name, data)
}

func (s *driveStorage) putInline(ctx context.Context, name string, data []byte) error {
	flat := flatten(name)

	body, err := json.Marshal(map[string]interface{}{
		"name":        flat,
		"parents":     []string{s.folder},
		"description": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return fmt.Errorf("xdrive: build the inline metadata: %w", err)
	}

	status, payload, err := s.do(ctx, http.MethodPost, driveFilesURL+"?fields=id",
		"application/json; charset=UTF-8", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("xdrive: Drive rejected the inline upload of %s with %d: %s", name, status, payload)
	}

	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return fmt.Errorf("xdrive: parse the Drive upload response: %w", err)
	}
	if parsed.ID != "" {
		s.rememberID(flat, parsed.ID)
	}
	return nil
}

func (s *driveStorage) putMedia(ctx context.Context, name string, data []byte) error {
	flat := flatten(name)

	metadata, err := json.Marshal(map[string]interface{}{
		"name":    flat,
		"parents": []string{s.folder},
	})
	if err != nil {
		return fmt.Errorf("xdrive: build the upload metadata: %w", err)
	}

	var body bytes.Buffer
	fmt.Fprintf(&body, "--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", driveBoundary)
	body.Write(metadata)
	fmt.Fprintf(&body, "\r\n--%s\r\nContent-Type: application/octet-stream\r\n\r\n", driveBoundary)
	body.Write(data)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", driveBoundary)

	status, payload, err := s.do(ctx, http.MethodPost, driveUploadURL,
		"multipart/related; boundary="+driveBoundary, body.Bytes())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("xdrive: Drive upload of %s answered %d: %s", name, status, payload)
	}

	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return fmt.Errorf("xdrive: parse the Drive upload response: %w", err)
	}
	if parsed.ID != "" {
		s.rememberID(flat, parsed.ID)
	}
	return nil
}

func (s *driveStorage) Get(ctx context.Context, name string) ([]byte, error) {
	flat := flatten(name)
	id, err := s.resolveID(ctx, flat)
	if err != nil {
		return nil, err
	}

	status, payload, err := s.do(ctx, http.MethodGet,
		driveFilesURL+"/"+url.PathEscape(id)+"?alt=media&supportsAllDrives=true", "", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		if len(payload) > 0 {
			return payload, nil
		}
		return s.getInline(ctx, id)
	case http.StatusNotFound:
		s.forgetID(flat)
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("xdrive: Drive download of %s answered %d: %s", name, status, payload)
	}
}

func (s *driveStorage) getInline(ctx context.Context, id string) ([]byte, error) {
	status, payload, err := s.do(ctx, http.MethodGet,
		driveFilesURL+"/"+url.PathEscape(id)+"?fields=description&supportsAllDrives=true", "", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("xdrive: Drive answered %d for inline data: %s", status, payload)
	}

	var parsed struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, fmt.Errorf("xdrive: parse the inline data: %w", err)
	}
	if parsed.Description == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(parsed.Description)
	if err != nil {
		return nil, fmt.Errorf("xdrive: the inline data is not valid base64: %w", err)
	}
	return data, nil
}

func (s *driveStorage) deleteID(ctx context.Context, flat, id string) error {
	status, payload, err := s.do(ctx, http.MethodDelete,
		driveFilesURL+"/"+url.PathEscape(id)+"?supportsAllDrives=true", "", nil)
	if err != nil {
		return err
	}
	s.forgetID(flat)
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("xdrive: Drive deletion of %s answered %d: %s", flat, status, payload)
	}
}

func (s *driveStorage) Delete(ctx context.Context, name string) error {
	flat := flatten(name)

	if id, err := s.resolveID(ctx, flat); err == nil {
		if err := s.deleteID(ctx, flat, id); err != nil {
			return err
		}
	} else if err != errNotFound {
		return err
	}

	children, err := s.query(ctx, "name contains '"+quoteDriveValue(flat+flatSeparator)+"'")
	if err != nil {
		return err
	}
	for childName, file := range children {
		if err := s.deleteID(ctx, childName, file.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *driveStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	flat := flatten(prefix) + flatSeparator

	found, err := s.query(ctx, "name contains '"+quoteDriveValue(flat)+"'")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(found))
	entries := make([]Entry, 0, len(found))
	for name, file := range found {
		rest := strings.TrimPrefix(name, flat)
		if rest == "" {
			continue
		}
		direct := true
		if cut := strings.Index(rest, flatSeparator); cut >= 0 {
			rest = rest[:cut]
			direct = false
		}
		if seen[rest] {
			continue
		}
		seen[rest] = true

		entry := Entry{Name: rest}
		if direct && file.description != "" {
			if data, err := base64.StdEncoding.DecodeString(file.description); err == nil {
				entry.Inline = data
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *driveStorage) Close() error {
	return nil
}
