# go-ossec
Package for interacting with OSSEC over SSH

# Example

Error handling omitted 

```go
import (
  "os"
  "fmt"

  "github.com/bhoriuchi/go-ossec"
)

func main() {
	client, _ := New(&Options{
		Username:      os.Getenv("OSSEC_USER"),
		Password:      os.Getenv("OSSEC_PASSWORD"),
		Host:          os.Getenv("OSSEC_SERVER"),
		IgnoreHostKey: true,
		Debug:         false,
	})

  defer client.Close()

  // list all agents
  agentList, _ := client.List()

  // find a specific agent by name
  agent, _ := client.Find("name", "foo.bar.com")

  // import an agent
  agent, _ = client.Import("foo.bar.com", "")

  // get the agent's key
  key, _ := client.Key(agent.ID)

  // remove an agent
  client.Remove(agent.ID)
}
```