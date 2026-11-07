package main

// Presentation helpers shared by every command: terminal detection, progress
// notes, tables, typo suggestions and the "what to do next" hints of errors.

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/tarnan3751/password-vault/internal/client"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// Nothing in fvault's output is coloured, so NO_COLOR and pipes need no special
// handling; every status is spelled out in words.

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// working tells the user, on stderr and only on a terminal, what is taking
// time. Nothing is printed if the work finishes within a moment. Call the
// returned function when the work is done.
func (a *app) working(msg string) func() {
	if !isTerminal(a.stderr) {
		return func() {}
	}
	var mu sync.Mutex
	shown, done := false, false
	t := time.AfterFunc(700*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			shown = true
			fmt.Fprint(a.stderr, msg+"...")
		}
	})
	return func() {
		t.Stop()
		mu.Lock()
		defer mu.Unlock()
		done = true
		if shown {
			fmt.Fprint(a.stderr, "\r\x1b[K")
		}
	}
}

// table prints rows under a header. A header ending in "*" marks a column that
// may be shortened (with "…") so the table fits an 80-column or narrower
// terminal; nothing is cut when the output is piped.
func (a *app) table(header []string, rows [][]string) {
	flex := make([]bool, len(header))
	w := make([]int, len(header))
	for i, h := range header {
		if flex[i] = strings.HasSuffix(h, "*"); flex[i] {
			header[i] = strings.TrimSuffix(h, "*")
		}
		w[i] = utf8.RuneCountInString(header[i])
	}
	for _, r := range rows {
		for i, c := range r {
			w[i] = max(w[i], utf8.RuneCountInString(c))
		}
	}
	if limit := cmp.Or(a.cols, termWidth(a.stdout)); limit > 0 {
		for sum(w)+2*(len(w)-1) > limit {
			widest := -1
			for i := range w {
				if flex[i] && w[i] > 8 && (widest < 0 || w[i] > w[widest]) {
					widest = i
				}
			}
			if widest < 0 {
				break
			}
			w[widest]--
		}
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, c := range cells {
			if n := utf8.RuneCountInString(c); n > w[i] {
				c = string([]rune(c)[:w[i]-1]) + "…"
			}
			b.WriteString(c)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", w[i]-utf8.RuneCountInString(c)+2))
			}
		}
		fmt.Fprintln(a.stdout, strings.TrimRight(b.String(), " "))
	}
	line(header)
	for _, r := range rows {
		line(r)
	}
}

func sum(n []int) (t int) {
	for _, x := range n {
		t += x
	}
	return t
}

// termWidth is the width of the terminal behind w, or 0 if w is not one.
func termWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if n, _, err := term.GetSize(int(f.Fd())); err == nil {
			return n
		}
	}
	return 0
}

// suggest returns the option closest to word (a likely typo), or "".
func suggest(word string, options []string) string {
	best, bestD := "", 3
	for _, o := range options {
		d := editDistance(word, o)
		if strings.HasPrefix(o, word) && len(word) >= 2 {
			d = 1
		}
		if d < bestD {
			best, bestD = o, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func commandNames() []string {
	n := make([]string, len(commands))
	for i, c := range commands {
		n[i] = c.name
	}
	return append(n, "help")
}

// didYouMean formats " Did you mean X?" for a mistyped word, or "".
func didYouMean(word string, options []string) string {
	if s := suggest(word, options); s != "" {
		return fmt.Sprintf(" Did you mean %q?", s)
	}
	return ""
}

// hint says what to do next for the errors a new user is likely to meet.
func hint(err error) string {
	var nf *client.NotFoundError
	switch {
	case errors.Is(err, client.ErrWrongPassword):
		return "check the master password (it is case-sensitive); if you meant another account, run `fvault login --username NAME`"
	case errors.As(err, &nf):
		switch nf.Kind {
		case "item":
			return "run `fvault ls` to see the items you can read"
		case "vault":
			return "run `fvault vault ls` to see your vaults"
		case "user":
			return "run `fvault contacts` to see the household members"
		}
	case errors.Is(err, client.ErrNotConfigured):
		return "for example: fvault init --server https://vault.example:8443 (the address your administrator gave you)"
	}
	return ""
}

// flagNames lists the flags of a command, for typo suggestions.
func flagNames(f *cmdFlags) []string {
	var n []string
	f.VisitAll(func(fl *flag.Flag) { n = append(n, fl.Name) })
	sort.Strings(n)
	return n
}

// say prints a paragraph of prose. On a terminal it is wrapped at word
// boundaries to the terminal width (at most 80); otherwise it is printed as is.
func (a *app) say(w io.Writer, s string) {
	width := min(cmp.Or(a.cols, termWidth(w)), 80)
	if !isTerminal(w) && a.cols == 0 {
		width = 0
	}
	fmt.Fprintln(w, wrapText(strings.TrimRight(s, "\n"), width))
}

// wrapText wraps each line at word boundaries to width columns; a wrapped
// line keeps the indentation of the line it came from. width <= 0 does nothing.
func wrapText(s string, width int) string {
	if width <= 0 {
		return s
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if utf8.RuneCountInString(l) <= width {
			out = append(out, l) // fits: keep its spacing
			continue
		}
		indent := l[:len(l)-len(strings.TrimLeft(l, " "))]
		cur := ""
		for _, word := range strings.Fields(l) {
			switch {
			case cur == "":
				cur = indent + word
			case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(word) > width:
				out = append(out, cur)
				cur = indent + word
			default:
				cur += " " + word
			}
		}
		if cur == "" {
			cur = l // blank line
		}
		out = append(out, cur)
	}
	return strings.Join(out, "\n")
}

// verifiedLabel is the VERIFIED column of the member and contact tables.
func verifiedLabel(self, keyChanged, verified bool) string {
	switch {
	case self:
		return "(you)"
	case keyChanged:
		return "KEY CHANGED - DO NOT TRUST"
	case verified:
		return "yes"
	}
	return "no"
}

// modeSentence says in plain words what a session mode means.
func modeSentence(m client.Mode) string {
	switch m {
	case client.ModeOnline:
		return "online: up to date, you can read and save"
	case client.ModeStale:
		return "no majority of the servers (2 of 3) can be reached: you see the last copy one server has, which may be out of date; saving is off"
	case client.ModeOlder:
		return "the servers show older data than this device has seen (see `fvault recover`); saving is off"
	}
	return "offline: no server can be reached, you see the copy saved on this device; saving is off"
}

const fingerprintExplained = "A fingerprint is a short code that identifies a person's key. To trust someone's key, compare their fingerprint with them in person or on a phone call, not through this app."

// passwordRules is stated before every "choose a master password" prompt.
const passwordRules = "Rules: at least 12 characters, not containing your username, not a very common password or an obvious pattern. Four or more unrelated words (like a short sentence) work well."

// passwordCheck is applied right after the first entry of a new master password.
func (a *app) passwordCheck(username string) func(string) error {
	return func(pw string) error {
		if err := vaultcrypto.CheckMasterPassword(pw, username); err != nil {
			return fmt.Errorf("master password not accepted: %w", err)
		}
		return nil
	}
}
