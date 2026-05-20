package breachwatch

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lazuli.dev/runtime/lazuli"
	"lazuli.dev/runtime/lazuli/breach"
)

const (
	adapterRef     = "@plugin/breach-watch"
	defaultBaseURL = "https://api.pwnedpasswords.com"
)

// Checker implements breach.Checker with HIBP's range API.
type Checker struct {
	client  *http.Client
	baseURL string
}

var _ breach.Checker = (*Checker)(nil)

func init() {
	lazuli.RegisterAdapter(adapterRef, New())
}

func New() *Checker {
	return NewWithClient(defaultBaseURL, &http.Client{Timeout: 5 * time.Second})
}

func NewWithClient(baseURL string, client *http.Client) *Checker {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Checker{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (c *Checker) PasswordBreached(ctx context.Context, password string) (int, error) {
	// Compute SHA-1 of password, send first 5 hex chars to
	// https://api.pwnedpasswords.com/range/<prefix>. Response lines are
	// <suffix>:<count>; the full suffix match happens locally.
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "lazuli-plugin-breach-watch")

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return 0, breach.ErrCheckerTimeout
		}
		return 0, fmt.Errorf("%w: %v", breach.ErrCheckerUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("%w: hibp status %d", breach.ErrCheckerUnavailable, resp.StatusCode)
	}
	return findSuffixCount(resp.Body, suffix)
}

func (c *Checker) Close() error { return nil }

func findSuffixCount(r io.Reader, want string) (int, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		suffix, rawCount, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ":")
		if !ok || !strings.EqualFold(suffix, want) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(rawCount))
		if err != nil {
			return 0, fmt.Errorf("parse HIBP breach count: %w", err)
		}
		return count, nil
	}
	return 0, scanner.Err()
}
