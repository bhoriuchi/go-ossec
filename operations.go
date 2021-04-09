package ossec

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	keyRx   = regexp.MustCompile(`(?m)(\S{20,})`)
	entryRx = regexp.MustCompile(`(?i)^\s*ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP:\s*(\S+)\s*$`)
)

// Remove removes a host from ossec
func (c *Client) Remove(id string) error {
	sudo := "sudo"
	if c.noSudo {
		sudo = ""
	}

	removeCmd := strings.TrimSpace(
		fmt.Sprintf(
			"%s %s -r %s",
			sudo,
			c.manageExec,
			id,
		),
	)

	s, err := c.run(removeCmd)
	if err != nil {
		return fmt.Errorf("failed to remove the host: %v", err)
	}

	agent, err := c.Find("id", id)
	if err != nil {
		return err
	}

	if agent != nil {
		return fmt.Errorf("agent was not removed: %s", s)
	}

	return nil
}

// Finds an agent using a regex search on the name
func (c *Client) Find(searchKey, searchValue string) (*Agent, error) {
	if searchKey == "" {
		searchKey = "name"
	}

	// validate the search key
	switch searchKey {
	case "id", "name", "ip":
		break
	default:
		return nil, fmt.Errorf("search key %q is invalid", searchKey)
	}

	list, err := c.List()
	if err != nil {
		return nil, err
	}

	for _, item := range list {
		value := ""

		switch searchKey {
		case "id":
			value = item.ID
		case "name":
			value = item.Name
		case "ip":
			value = item.IP
		default:
			return nil, fmt.Errorf("search key %q is invalid", searchKey)
		}

		if strings.TrimSpace(strings.ToLower(value)) == strings.TrimSpace(strings.ToLower(searchValue)) {
			return item, nil
		}
	}

	return nil, nil
}

// List lists all ossec agents
func (c *Client) List() ([]*Agent, error) {
	sudo := "sudo"
	if c.noSudo {
		sudo = ""
	}

	list := []*Agent{}

	listCmd := strings.TrimSpace(
		fmt.Sprintf(
			"%s %s -l",
			sudo,
			c.manageExec,
		),
	)

	s, err := c.run(listCmd)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Printf("-- Start Raw Response --\n%s\n-- End Raw Response--\n", s)
	}

	for _, item := range strings.Split(s, "\n") {
		matches := entryRx.FindAllStringSubmatch(item, -1)
		if len(matches) == 0 {
			continue
		}

		list = append(list, &Agent{
			ID:   matches[0][1],
			Name: matches[0][2],
			IP:   matches[0][3],
		})
	}

	return list, nil
}

// Import imports a host and returns its id and key
func (c *Client) Import(host, ip string) (*Agent, error) {
	importFile := filepath.Join(c.tempDir, fmt.Sprintf("ossec_import.%s.lst", host))

	if host == "" {
		return nil, fmt.Errorf("no host specified")
	}
	if ip == "" {
		ip = "any"
	}

	agent, err := c.Find("name", host)
	if err != nil {
		return nil, err
	}

	// if the agent was found, throw error
	if agent != nil {
		return agent, fmt.Errorf("agent with Name: %s was found with ID: %s, IP: %s", agent.Name, agent.ID, agent.IP)
	}

	sudo := "sudo"
	if c.noSudo {
		sudo = ""
	}

	entryCmd := strings.TrimSpace(
		fmt.Sprintf(
			"%s echo \"%s,%s\" >%s",
			sudo,
			ip,
			host,
			importFile,
		),
	)

	importCmd := strings.TrimSpace(
		fmt.Sprintf(
			"%s %s -f %s",
			sudo,
			c.manageExec,
			importFile,
		),
	)

	removeCmd := strings.TrimSpace(
		fmt.Sprintf(
			"%s rm -f %s",
			sudo,
			importFile,
		),
	)

	// perform import
	_, err = c.run(
		fmt.Sprintf("%s && %s && %s", entryCmd, importCmd, removeCmd),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to import the host: %v", err)
	}

	newAgent, err := c.Find("name", host)
	if err != nil {
		return nil, err
	} else if newAgent == nil {
		return nil, fmt.Errorf("import unsuccessful, host %s not found", host)
	}

	return newAgent, nil
}

// gets the key
func (c *Client) Key(id string) (string, error) {
	sudo := "sudo"
	if c.noSudo {
		sudo = ""
	}

	s, err := c.run(
		strings.TrimSpace(
			fmt.Sprintf(
				"%s %s -e %s",
				sudo,
				c.manageExec,
				id,
			),
		),
	)

	if c.debug {
		fmt.Printf("-- Start Raw Response --\n%s\n-- End Raw Response--\n", s)
	}

	if err != nil {
		return "", fmt.Errorf("failed to export the key: %v", err)
	}

	matches := keyRx.FindAllStringSubmatch(s, 1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no key found in parsed output")
	}

	return matches[0][1], nil
}
