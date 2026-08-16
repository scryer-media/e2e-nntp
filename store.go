package nntp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const defaultGroup = "alt.binaries.test"

type articleStore struct {
	mu        sync.RWMutex
	directory string
	articles  map[string]struct{}
}

func openArticleStore(directory string) (*articleStore, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create article directory: %w", err)
	}
	store := &articleStore{directory: directory, articles: make(map[string]struct{})}
	if _, err := store.reload(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *articleStore) path(messageID string) string {
	return filepath.Join(store.directory, url.PathEscape(messageID))
}

func (store *articleStore) count() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.articles)
}

func (store *articleStore) exists(messageID string) bool {
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, exists := store.articles[messageID]
	return exists
}

func (store *articleStore) load(messageID string) ([]byte, bool) {
	store.mu.RLock()
	_, exists := store.articles[messageID]
	store.mu.RUnlock()
	if !exists {
		return nil, false
	}
	contents, err := os.ReadFile(store.path(messageID))
	if err != nil {
		return nil, false
	}
	return contents, true
}

func (store *articleStore) commit(messageID, temporaryPath string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.articles[messageID]; exists {
		return os.ErrExist
	}
	if err := os.Rename(temporaryPath, store.path(messageID)); err != nil {
		return err
	}
	store.articles[messageID] = struct{}{}
	return nil
}

func (store *articleStore) deleteByID(messageID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.articles[messageID]; !exists {
		return false, nil
	}
	if err := os.Remove(store.path(messageID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	delete(store.articles, messageID)
	return true, nil
}

func (store *articleStore) deleteByPrefix(prefix string, percentage int) (matched, deleted int, err error) {
	if percentage < 0 || percentage > 100 {
		return 0, 0, errors.New("percentage must be between 0 and 100")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	ids := make([]string, 0)
	for messageID := range store.articles {
		if strings.HasPrefix(messageID, prefix) {
			ids = append(ids, messageID)
		}
	}
	sort.Strings(ids)
	matched = len(ids)
	limit := matched * percentage / 100
	for _, messageID := range ids[:limit] {
		if removeErr := os.Remove(store.path(messageID)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return matched, deleted, removeErr
		}
		delete(store.articles, messageID)
		deleted++
	}
	return matched, deleted, nil
}

func (store *articleStore) reload() (int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return 0, fmt.Errorf("read article directory: %w", err)
	}
	articles := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".incoming-") {
			continue
		}
		messageID, unescapeErr := url.PathUnescape(entry.Name())
		if unescapeErr != nil || messageID == "" {
			continue
		}
		articles[messageID] = struct{}{}
	}
	store.articles = articles
	return len(articles), nil
}

func readPostedArticle(reader *bufio.Reader, directory string) (messageID, temporaryPath string, written int, err error) {
	temporary, err := os.CreateTemp(directory, ".incoming-*")
	if err != nil {
		return "", "", 0, fmt.Errorf("create temporary article: %w", err)
	}
	temporaryPath = temporary.Name()
	writer := bufio.NewWriter(temporary)
	cleanup := func(cause error) (string, string, int, error) {
		_ = writer.Flush()
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return "", "", written, cause
	}

	var header bytes.Buffer
	inHeaders := true
	for {
		line, readErr := readLine(reader)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return cleanup(errors.New("posting connection ended before terminator"))
			}
			return cleanup(readErr)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if inHeaders {
			if line == "" {
				inHeaders = false
			} else {
				header.WriteString(line)
				header.WriteByte('\n')
			}
		}
		count, writeErr := writer.WriteString(line + "\r\n")
		written += count
		if writeErr != nil {
			return cleanup(writeErr)
		}
	}
	if err := writer.Flush(); err != nil {
		return cleanup(err)
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(err)
	}
	if err := temporary.Close(); err != nil {
		return cleanup(err)
	}
	messageID = messageIDFromHeaders(header.String())
	if messageID == "" {
		return cleanup(errors.New("posted article has no message ID"))
	}
	return messageID, temporaryPath, written, nil
}

func messageIDFromHeaders(headers string) string {
	for _, line := range strings.Split(headers, "\n") {
		if len(line) < len("message-id:") || !strings.EqualFold(line[:len("message-id:")], "message-id:") {
			continue
		}
		return stripBrackets(strings.TrimSpace(line[len("message-id:"):]))
	}
	return ""
}

func articleBody(article []byte) []byte {
	trimmed := bytes.TrimLeft(article, "\r\n")
	if bytes.HasPrefix(trimmed, []byte("=ybegin")) {
		return article
	}
	for _, separator := range [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")} {
		if split := bytes.Index(article, separator); split >= 0 && looksLikeHeaders(article[:split]) {
			return article[split+len(separator):]
		}
	}
	return article
}

func looksLikeHeaders(block []byte) bool {
	for _, line := range bytes.Split(block, []byte("\n")) {
		lower := strings.ToLower(strings.TrimSpace(strings.TrimRight(string(line), "\r")))
		for _, name := range []string{"path:", "message-id:", "subject:", "from:", "date:"} {
			if strings.HasPrefix(lower, name) {
				return true
			}
		}
	}
	return false
}

func stripBrackets(value string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(value), "<"), ">")
}
