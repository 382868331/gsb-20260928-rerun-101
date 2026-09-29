// Command evaudit is a small CLI over the auditlog package.
//
// Subcommands:
//
//	init     <log>
//	append   <log> <type> <source> [id] [data-base64]
//	seal     <log> <batch-id> <summary-out>
//	verify   <log> [summary]
//	list     <log>
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"evidenceaudit/auditlog"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	cmd, logPath := os.Args[1], os.Args[2]
	var err error
	switch cmd {
	case "init":
		_, err = auditlog.Create(logPath)
	case "append":
		err = appendCmd(logPath, os.Args[3:])
	case "seal":
		err = sealCmd(logPath, os.Args[3:])
	case "verify":
		err = verifyCmd(logPath, os.Args[3:])
	case "list":
		err = listCmd(logPath)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: evaudit <init|append|seal|verify|list> <log> [args...]")
	os.Exit(2)
}

func appendCmd(path string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("append needs <type> <source> [id] [data-base64]")
	}
	l, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer l.Close()
	ev := auditlog.Event{Time: time.Now().UTC(), EventType: args[0], Source: args[1]}
	if len(args) >= 3 {
		ev.ID = args[2]
	}
	if len(args) >= 4 {
		ev.Data, err = base64.StdEncoding.DecodeString(args[3])
		if err != nil {
			return err
		}
	}
	if err := l.Append(ev); err != nil {
		return err
	}
	fmt.Printf("appended; records=%d\n", l.Count())
	return nil
}

func sealCmd(path string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("seal needs <batch-id> <summary-out>")
	}
	l, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer l.Close()
	s, err := l.Seal(args[0])
	if err != nil {
		return err
	}
	if err := auditlog.WriteSummary(args[1], s); err != nil {
		return err
	}
	fmt.Printf("sealed batch %q: %d records, summary -> %s\n", s.BatchID, s.RecordCount, args[1])
	return nil
}

func verifyCmd(path string, args []string) error {
	if len(args) == 0 {
		res, err := auditlog.VerifyChain(path)
		if err != nil {
			return err
		}
		fmt.Printf("chain OK: %d records; (tail truncation requires a summary)\n", res.RecordCount)
		return nil
	}
	s, err := auditlog.ReadSummary(args[0])
	if err != nil {
		return err
	}
	res, err := auditlog.VerifyAgainstSummary(path, s)
	if err != nil {
		return err
	}
	fmt.Printf("sealed batch %q verified OK: %d records\n", s.BatchID, res.RecordCount)
	return nil
}

func listCmd(path string) error {
	l, err := auditlog.Open(path)
	if err != nil {
		return err
	}
	defer l.Close()
	enc := json.NewEncoder(os.Stdout)
	return l.Scan(func(r auditlog.Record) error {
		return enc.Encode(struct {
			Index     uint64 `json:"index"`
			Time      string `json:"time_utc"`
			EventType string `json:"type"`
			Source    string `json:"source"`
			ID        string `json:"id"`
			DataB64   string `json:"data_b64"`
		}{
			Index:     r.Index,
			Time:      r.Time.Format(time.RFC3339Nano),
			EventType: r.EventType,
			Source:    r.Source,
			ID:        r.ID,
			DataB64:   base64.StdEncoding.EncodeToString(r.Data),
		})
	})
}
