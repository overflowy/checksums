package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	jobQueueSize = 1000
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
)

type Config struct {
	RootDir    string
	Algo       string
	NumWorkers int
	OutputExt  string
	Update     bool
	Excludes   []string
	HashFunc   func() hash.Hash
}

type FileResult struct {
	Path  string
	Hash  string
	Size  int64
	Err   error
	IsNew bool
}

var totalBytes int64

func main() {
	algoFlag := flag.String("algo", "sha256", "Algorithm: md5, sha256, sha512")
	updateFlag := flag.Bool("update", false, "Only hash new files missing from existing checksum file")
	excludeFlag := flag.String("exclude", "", "Comma-separated list of names to skip (e.g. .git,node_modules)")
	workersFlag := flag.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
	flag.Parse()

	var hashFunc func() hash.Hash
	var ext string
	switch strings.ToLower(*algoFlag) {
	case "md5":
		hashFunc = md5.New
		ext = ".md5"
	case "sha512":
		hashFunc = sha512.New
		ext = ".sha512"
	default:
		hashFunc = sha256.New
		ext = ".sha256"
	}

	targetDir := "."
	if args := flag.Args(); len(args) > 0 {
		targetDir = args[0]
	}
	absPath, _ := filepath.Abs(targetDir)

	excludes := []string{".tmp", "checksums" + ext}
	if *excludeFlag != "" {
		excludes = append(excludes, strings.Split(*excludeFlag, ",")...)
	}

	cfg := Config{
		RootDir:    absPath,
		Algo:       *algoFlag,
		NumWorkers: *workersFlag,
		OutputExt:  ext,
		Update:     *updateFlag,
		Excludes:   excludes,
		HashFunc:   hashFunc,
	}

	checksumFile := "checksums" + cfg.OutputExt
	if _, err := os.Stat(filepath.Join(cfg.RootDir, checksumFile)); err == nil && !cfg.Update {
		verify(cfg, checksumFile)
	} else {
		generate(cfg, checksumFile)
	}
}

func generate(cfg Config, checksumFileName string) {
	start := time.Now()
	existing := make(map[string]string)
	if cfg.Update {
		existing = readChecksumMap(filepath.Join(cfg.RootDir, checksumFileName))
		fmt.Printf("Updating %s (skipping %d existing files)...\n", checksumFileName, len(existing))
	}

	jobs := make(chan string, jobQueueSize)
	resultsChan := make(chan FileResult, jobQueueSize)
	var wg sync.WaitGroup

	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				h, size, err := hashFile(path, cfg.HashFunc)
				resultsChan <- FileResult{Path: path, Hash: h, Size: size, Err: err, IsNew: true}
			}
		}()
	}

	go func() {
		filepath.WalkDir(cfg.RootDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := d.Name()
			for _, ex := range cfg.Excludes {
				if strings.Contains(path, ex) || name == ex {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(cfg.RootDir, path)
				if _, ok := existing[filepath.ToSlash(rel)]; !ok {
					jobs <- path
				} else {
					resultsChan <- FileResult{Path: path, Hash: existing[filepath.ToSlash(rel)], IsNew: false}
				}
			}
			return nil
		})
		close(jobs)
	}()

	go func() { wg.Wait(); close(resultsChan) }()

	var results []FileResult
	var processed int64
	for res := range resultsChan {
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "\n%sError: %s (%v)%s\n", colorRed, res.Path, res.Err, colorReset)
			continue
		}
		results = append(results, res)
		if res.IsNew {
			atomic.AddInt64(&processed, 1)
			fmt.Fprintf(os.Stderr, "\rHashing: %d files... (%s)", atomic.LoadInt64(&processed), formatBytes(atomic.LoadInt64(&totalBytes)))
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })

	tmpPath := filepath.Join(cfg.RootDir, checksumFileName+".tmp")
	f, _ := os.Create(tmpPath)
	bw := bufio.NewWriter(f)
	for _, res := range results {
		rel, _ := filepath.Rel(cfg.RootDir, res.Path)
		fmt.Fprintf(bw, "%s  %s\n", res.Hash, filepath.ToSlash(rel))
	}
	bw.Flush()
	f.Close()
	os.Rename(tmpPath, filepath.Join(cfg.RootDir, checksumFileName))

	elapsed := time.Since(start)
	speed := float64(atomic.LoadInt64(&totalBytes)) / elapsed.Seconds()
	totalSize := atomic.LoadInt64(&totalBytes)

	fmt.Printf("\r%-80s\rOutput file:   %s\n", "", checksumFileName)
	fmt.Printf("Total files:   %d\n", len(results))
	fmt.Printf("Total size:    %s\n", formatBytes(totalSize))
	fmt.Printf("Average speed: %s/s\n", formatBytes(int64(speed)))
	fmt.Printf("Time elapsed:  %v\n", elapsed.Round(time.Millisecond))
}

func verify(cfg Config, checksumFileName string) {
	checksumPath := filepath.Join(cfg.RootDir, checksumFileName)
	f, err := os.Open(checksumPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open checksum file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	jobs := make(chan string, jobQueueSize)
	results := make(chan string, jobQueueSize)
	var wg sync.WaitGroup

	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range jobs {
				p := strings.Fields(line)
				if len(p) < 2 {
					continue
				}
				rel := filepath.FromSlash(strings.Join(p[1:], " "))
				full := filepath.Join(cfg.RootDir, rel)
				h, _, err := hashFile(full, cfg.HashFunc)
				if err != nil {
					results <- colorRed + "[MISSING] " + rel + colorReset
				} else if h == p[0] {
					results <- colorGreen + "[OK]      " + rel + colorReset
				} else {
					results <- colorRed + "[FAILED]  " + rel + colorReset
				}
			}
		}()
	}

	go func() {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			jobs <- scanner.Text()
		}
		close(jobs)
	}()

	go func() { wg.Wait(); close(results) }()

	errorCount := 0
	checked := 0
	for msg := range results {
		fmt.Println(msg)
		checked++
		if strings.Contains(msg, "[FAILED]") || strings.Contains(msg, "[MISSING]") {
			errorCount++
		}
	}
	if errorCount == 1 {
		fmt.Printf("%s1 error found.%s\n", colorRed, colorReset)
		os.Exit(1)
	}
	if errorCount > 0 {
		fmt.Printf("%s%d errors found.%s\n", colorRed, errorCount, colorReset)
		os.Exit(1)
	}
	fmt.Printf("No errors found.\n")
}

func hashFile(path string, factory func() hash.Hash) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := factory()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	atomic.AddInt64(&totalBytes, n)
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readChecksumMap(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		p := strings.Fields(s.Text())
		if len(p) >= 2 {
			m[p[1]] = p[0]
		}
	}
	return m
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
