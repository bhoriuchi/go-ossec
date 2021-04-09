package ossec

import (
	"os"
	"testing"
)

// TestOSSEC test functionality
func TestOSSEC(t *testing.T) {
	client, err := New(&Options{
		Username:      os.Getenv("OSSEC_USER"),
		Password:      os.Getenv("OSSEC_PASSWORD"),
		Host:          os.Getenv("OSSEC_SERVER"),
		IgnoreHostKey: true,
		Debug:         false,
	})

	if err != nil {
		t.Errorf("failed to create client: %s", err)
		return
	}

	agent, err := client.Import("foo101.bar.com", "")
	if err != nil {
		t.Errorf("failed to import agent: %s", err)
		return
	}

	key, err := client.Key(agent.ID)
	if err != nil {
		t.Errorf("failed to get key for agent %s: %s", agent.Name, err)
		return
	}

	if len(key) < 1 {
		t.Errorf("No key returned")
		return
	}

	err = client.Remove(agent.ID)
	if err != nil {
		t.Errorf("failed to remove agent: %s", err)
		return
	}
}
