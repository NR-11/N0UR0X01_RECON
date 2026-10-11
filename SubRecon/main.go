// subrecon - automated subdomain enumeration workflow
//
// This tool runs the exact pipeline described in SUBDOMAIN_ENUMERATION.md:
// passive enum (subfinder, github-subdomains, gitlab-subdomains, gau)
// -> active bruteforce (puredns)
// -> merge/resolve/probe (dnsx, httpx)
// -> scraping (katana)
// -> permutations (alterx, puredns)
// -> final output + triage (status_404 / status_403)
// -> screenshots (gowitness)
// -> per-tool stats
//
// Run it, answer the setup questions once, and it does the rest on its own.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- config ----------

type Config struct {
	Domain   string // e.g. wolt.com
	Platform string // e.g. h1
	BaseDir  string // e.g. wolt.com_h1

	SubdomainsDir  string
	UrlsDir        string
	ResolversDir   string
	WordlistsDir   string
	ScreenshotsDir string

	GithubToken string
	GitlabToken string

	WordlistFile          string
	ResolversFile         string
	ResolversTrustedFile  string
}

var reader = bufio.NewReader(os.Stdin)

func main() {
	banner()

	cfg := setup()

	checkRequiredTools()

	fmt.Println()
	section("PASSIVE ENUMERATION")
	passiveEnum(cfg)

	fmt.Println()
	section("ACTIVE ENUMERATION (bruteforce)")
	activeBrute(cfg)

	fmt.Println()
	section("MERGE + RESOLVE + PROBE")
	mergeResolveProbe(cfg)

	fmt.Println()
	section("SCRAPING (katana)")
	scraping(cfg)

	fmt.Println()
	section("PERMUTATIONS (alterx)")
	permutations(cfg)

	fmt.Println()
	section("FINAL OUTPUT")
	finalOutput(cfg)

	fmt.Println()
	section("SCREENSHOTS (gowitness)")
	screenshots(cfg)

	fmt.Println()
	section("STATS")
	printStats(cfg)

	fmt.Println()
	fmt.Println("[✓] Done. Everything is under:", cfg.BaseDir)
}

// ---------- setup / prompts ----------

func setup() Config {
	var cfg Config

	cfg.Domain = ask("Target domain (e.g. wolt.com): ")
	cfg.Domain = strings.TrimSpace(cfg.Domain)
	if cfg.Domain == "" {
		fatal("a target domain is required.")
	}

	cfg.Platform = ask("Platform short name (e.g. h1, bugcrowd, intigriti): ")
	cfg.Platform = strings.TrimSpace(cfg.Platform)
	if cfg.Platform == "" {
		cfg.Platform = "recon"
	}

	cfg.BaseDir = fmt.Sprintf("%s_%s", cfg.Domain, cfg.Platform)

	cfg.SubdomainsDir = filepath.Join(cfg.BaseDir, "subdomains")
	cfg.UrlsDir = filepath.Join(cfg.BaseDir, "urls")
	cfg.WordlistsDir = filepath.Join(cfg.BaseDir, "wordlists")
	cfg.ScreenshotsDir = filepath.Join(cfg.BaseDir, "screenshots")

	for _, d := range []string{cfg.SubdomainsDir, cfg.UrlsDir, cfg.WordlistsDir, cfg.ScreenshotsDir} {
		mustMkdir(d)
	}

	// --- subfinder API keys check ---
	checkSubfinderKeys()

	// --- github token ---
	cfg.GithubToken = ask("GitHub token (classic, public_repo scope) [leave empty to skip github-subdomains]: ")
	cfg.GithubToken = strings.TrimSpace(cfg.GithubToken)
	if cfg.GithubToken == "" {
		warn("no GitHub token given — github-subdomains will be skipped.")
	}

	// --- gitlab token ---
	cfg.GitlabToken = ask("GitLab token [leave empty to skip gitlab-subdomains]: ")
	cfg.GitlabToken = strings.TrimSpace(cfg.GitlabToken)
	if cfg.GitlabToken == "" {
		warn("no GitLab token given — gitlab-subdomains will be skipped.")
	}

	// --- wordlist path ---
	wl := ask("Path to an existing DNS wordlist [leave empty to auto-download best-dns-wordlist.txt]: ")
	wl = strings.TrimSpace(wl)
	if wl == "" {
		cfg.WordlistFile = filepath.Join(cfg.WordlistsDir, "best-dns-wordlist.txt")
		fmt.Println("[*] Downloading best-dns-wordlist.txt ...")
		mustDownload("https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt", cfg.WordlistFile)
	} else {
		if !fileExists(wl) {
			fatal("wordlist path does not exist: " + wl)
		}
		cfg.WordlistFile = wl
	}

	// --- resolvers download path ---
	rp := ask(fmt.Sprintf("Directory to store resolvers files [default: %s]: ", filepath.Join(cfg.BaseDir, "resolvers")))
	rp = strings.TrimSpace(rp)
	if rp == "" {
		rp = filepath.Join(cfg.BaseDir, "resolvers")
	}
	mustMkdir(rp)
	cfg.ResolversDir = rp
	cfg.ResolversFile = filepath.Join(rp, "resolvers.txt")
	cfg.ResolversTrustedFile = filepath.Join(rp, "resolvers-trusted.txt")

	fmt.Println()
	fmt.Println("[*] Updating resolvers (always re-downloaded before use)...")
	mustDownload("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", cfg.ResolversFile)
	mustDownload("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt", cfg.ResolversTrustedFile)
	fmt.Println("[✓] resolvers.txt and resolvers-trusted.txt are up to date.")

	return cfg
}

func checkSubfinderKeys() {
	home, err := os.UserHomeDir()
	if err != nil {
		warn("could not determine home directory, skipping subfinder key check.")
		return
	}
	cfgPath := filepath.Join(home, ".config", "subfinder", "provider-config.yaml")

	if !fileExists(cfgPath) {
		warn("subfinder provider-config.yaml not found at " + cfgPath)
		warn("subfinder will run passively without extra API keys (fewer results).")
		if !askYesNo("Continue anyway? [y/N]: ") {
			fatal("aborted by user.")
		}
		return
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		warn("could not read provider-config.yaml: " + err.Error())
		return
	}

	if !hasConfiguredKeys(string(data)) {
		warn("subfinder provider-config.yaml exists but looks EMPTY (no keys configured).")
		warn("subfinder will still run, but with far fewer sources/results.")
		if !askYesNo("Continue anyway? [y/N]: ") {
			fatal("aborted by user.")
		}
		return
	}

	fmt.Println("[✓] subfinder API keys found in", cfgPath)
}

// crude heuristic: a "configured" line is a non-empty, non-comment line
// that has something after the colon (i.e. not just "provider:").
func hasConfiguredKeys(content string) bool {
	lineRe := regexp.MustCompile(`^\s*-?\s*[A-Za-z0-9_]+\s*:\s*\S+`)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lineRe.MatchString(line) {
			return true
		}
	}
	return false
}

// ---------- required tools check ----------

func checkRequiredTools() {
	tools := []string{"subfinder", "gau", "puredns", "katana", "alterx", "dnsx", "httpx", "gowitness"}
	optional := map[string]string{
		"github-subdomains": "github-subdomains",
		"gitlab-subdomains": "gitlab-subdomains",
	}

	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	for name := range optional {
		if _, err := exec.LookPath(name); err != nil {
			warn(fmt.Sprintf("%s not found in PATH — that step will be skipped if a token was provided.", name))
		}
	}

	if len(missing) > 0 {
		warn("missing required tools: " + strings.Join(missing, ", "))
		if !askYesNo("Continue anyway (missing tools will just fail/skip)? [y/N]: ") {
			fatal("aborted by user.")
		}
	}
}

// ---------- PASSIVE ----------

func passiveEnum(cfg Config) {
	type job struct {
		name string
		run  func()
	}

	var jobs []job

	jobs = append(jobs, job{"subfinder", func() {
		runShell(cfg.SubdomainsDir,
			fmt.Sprintf(`subfinder -d %s -all -o sub_subfinder.txt`, cfg.Domain))
	}})

	if cfg.GithubToken != "" {
		jobs = append(jobs, job{"github-subdomains", func() {
			runShell(cfg.SubdomainsDir,
				fmt.Sprintf(`github-subdomains -d %s -t %s -o sub_github.txt`, cfg.Domain, cfg.GithubToken))
		}})
	}

	if cfg.GitlabToken != "" {
		jobs = append(jobs, job{"gitlab-subdomains", func() {
			runShell(cfg.SubdomainsDir,
				fmt.Sprintf(`gitlab-subdomains -d %s -t %s -o sub_gitlab.txt && mv %s.txt sub_gitlab.txt`,
					cfg.Domain, cfg.GitlabToken, cfg.Domain))
		}})
	}

	jobs = append(jobs, job{"gau", func() {
		runShell(cfg.SubdomainsDir,
			fmt.Sprintf(`gau --subs %s | sed -E 's#^https?://##; s#[/:?#].*##' | sort -u > sub_gau.txt`, cfg.Domain))
	}})

	done := make(chan string, len(jobs))
	for _, j := range jobs {
		go func(j job) {
			fmt.Printf("  [>] starting %s...\n", j.name)
			j.run()
			fmt.Printf("  [+] %s done\n", j.name)
			done <- j.name
		}(j)
	}
	for range jobs {
		<-done
	}
}

// ---------- ACTIVE (bruteforce) ----------

func activeBrute(cfg Config) {
	runShell(cfg.SubdomainsDir, fmt.Sprintf(
		`puredns bruteforce %s %s -r %s --resolvers-trusted %s --rate-limit 150 --rate-limit-trusted 50 -w sub_puredns.txt`,
		cfg.WordlistFile, cfg.Domain, cfg.ResolversFile, cfg.ResolversTrustedFile,
	))
}

// ---------- MERGE + RESOLVE + PROBE ----------

func mergeResolveProbe(cfg Config) {
	runShell(cfg.SubdomainsDir, `cat sub_*.txt | sort -u > all_subs.txt`)
	runShell(cfg.SubdomainsDir, `dnsx -l all_subs.txt -silent -o resolved.txt`)
	runShell(cfg.SubdomainsDir, `httpx -l resolved.txt -silent -o live_urls.txt`)
}

// ---------- SCRAPING ----------

func scraping(cfg Config) {
	katanaURLs := filepath.Join(cfg.UrlsDir, "katana_urls.txt")
	runShell(cfg.SubdomainsDir, fmt.Sprintf(
		`katana -list live_urls.txt -jc -d 2 -rl 50 -silent -o %s`, katanaURLs))

	runShell(cfg.SubdomainsDir, fmt.Sprintf(
		`cat %s | sed -E 's#^https?://##; s#[/:?#].*##' | grep -E "(^|\.)%s$" | sort -u > sub_katana.txt`,
		katanaURLs, regexp.QuoteMeta(cfg.Domain)))

	runShell(cfg.SubdomainsDir, `cat sub_*.txt | sort -u > all_subs.txt`)
}

// ---------- PERMUTATIONS ----------

func permutations(cfg Config) {
	runShell(cfg.SubdomainsDir, `alterx -l all_subs.txt -limit 50000 -o perms_raw.txt`)
	runShell(cfg.SubdomainsDir, fmt.Sprintf(
		`puredns resolve perms_raw.txt -r %s --resolvers-trusted %s --rate-limit 150 --rate-limit-trusted 50 -w perms.txt`,
		cfg.ResolversFile, cfg.ResolversTrustedFile))
}

// ---------- FINAL OUTPUT ----------

func finalOutput(cfg Config) {
	runShell(cfg.SubdomainsDir, `cat all_subs.txt perms.txt | sort -u > final_all_subs.txt`)
	runShell(cfg.SubdomainsDir, `httpx -l final_all_subs.txt -silent -sc -title -td -ip -o httpx.txt`)
	runShell(cfg.SubdomainsDir, `awk '{print $1}' httpx.txt | sort -u > final_live_subs.txt`)
	runShell(cfg.SubdomainsDir, `grep ' \[404\]' httpx.txt | awk '{print $1}' | sort -u > status_404.txt`)
	runShell(cfg.SubdomainsDir, `grep ' \[403\]' httpx.txt | awk '{print $1}' | sort -u > status_403.txt`)
}

// ---------- SCREENSHOTS ----------

func screenshots(cfg Config) {
	liveFile := filepath.Join(cfg.SubdomainsDir, "final_live_subs.txt")
	if !fileExists(liveFile) || countLines(liveFile) == 0 {
		warn("final_live_subs.txt is empty — skipping gowitness.")
		return
	}
	absScreens, _ := filepath.Abs(cfg.ScreenshotsDir)
	runShell(cfg.SubdomainsDir, fmt.Sprintf(
		`gowitness scan file -f final_live_subs.txt --screenshot-path %s -t 20`, absScreens))
}

// ---------- STATS ----------

func printStats(cfg Config) {
	d := cfg.SubdomainsDir

	tools := []struct {
		label string
		file  string
	}{
		{"subfinder", "sub_subfinder.txt"},
		{"github", "sub_github.txt"},
		{"gitlab", "sub_gitlab.txt"},
		{"gau", "sub_gau.txt"},
		{"puredns (brute)", "sub_puredns.txt"},
		{"katana", "sub_katana.txt"},
	}

	fmt.Println("Per-tool output:")
	for _, t := range tools {
		p := filepath.Join(d, t.file)
		fmt.Printf("  %-18s: %d\n", t.label, countLines(p))
	}

	fmt.Println()
	fmt.Println("Unique subdomains added vs subfinder alone:")
	base := readLinesAsSet(filepath.Join(d, "sub_subfinder.txt"))
	for _, t := range tools {
		if t.label == "subfinder" {
			continue
		}
		p := filepath.Join(d, t.file)
		other := readLinesAsSet(p)
		added := 0
		for k := range other {
			if !base[k] {
				added++
			}
		}
		fmt.Printf("  %-18s: +%d new\n", t.label, added)
	}

	fmt.Println()
	fmt.Println("Final files:")
	finalFiles := []string{"all_subs.txt", "final_all_subs.txt", "httpx.txt", "final_live_subs.txt", "status_404.txt", "status_403.txt"}
	for _, f := range finalFiles {
		p := filepath.Join(d, f)
		fmt.Printf("  %-20s: %d lines\n", f, countLines(p))
	}
}

// ---------- helpers: shell / process ----------

func runShell(dir string, cmdStr string) {
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		warn(fmt.Sprintf("command failed (continuing): %s\n    error: %v", cmdStr, err))
	}
}

// ---------- helpers: io ----------

func mustMkdir(path string) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		fatal("could not create directory " + path + ": " + err.Error())
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func readLinesAsSet(path string) map[string]bool {
	set := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return set
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			set[line] = true
		}
	}
	return set
}

func mustDownload(url, dest string) {
	if err := downloadFile(url, dest); err != nil {
		fatal(fmt.Sprintf("failed to download %s -> %s: %v", url, dest, err))
	}
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// ---------- helpers: prompt / output ----------

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func askYesNo(prompt string) bool {
	ans := strings.ToLower(strings.TrimSpace(ask(prompt)))
	return ans == "y" || ans == "yes"
}

func warn(msg string) {
	fmt.Println("[!] " + msg)
}

func fatal(msg string) {
	fmt.Println("[x] " + msg)
	os.Exit(1)
}

func section(title string) {
	fmt.Println(strings.Repeat("=", 10) + " " + title + " " + strings.Repeat("=", 10))
}

func banner() {
	fmt.Print(`
subrecon — automated subdomain enumeration workflow
(subfinder + github/gitlab-subdomains + gau + puredns + katana + alterx + dnsx/httpx + gowitness)

`)
}

// unused but kept for potential future flags (e.g. -version)
var _ = strconv.Itoa
var _ = sort.Strings
