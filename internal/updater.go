package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const githubReleasesAPI = "https://api.github.com/repos/HP-jh/TarsOpenClawSandbox/releases/latest"

// UpdateChecker queries GitHub for newer versions.
type UpdateChecker struct {
	client *http.Client
}

func NewUpdateChecker() *UpdateChecker {
	return &UpdateChecker{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func (u *UpdateChecker) LatestVersion() (string, error) {
	req, err := http.NewRequest("GET", githubReleasesAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API status %d", resp.StatusCode)
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// CompareVersions returns true if remote is newer than current.
// Expects semantic versions with leading 'v' stripped.
func CompareVersions(current, remote string) bool {
	cur := strings.TrimPrefix(current, "v")
	rem := strings.TrimPrefix(remote, "v")
	return rem != "" && rem != cur
}
