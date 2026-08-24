// Package mutation performs byte-exact request transformations. It deliberately
// does not parse requests through net/http.
package mutation

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var special = []byte{0, 9, 11, 12, 13, 127}
var base = []string{"vanilla", "underjoin1", "spacejoin1", "space1", "nameprefix1", "nameprefix2", "valueprefix1", "nospace1", "linewrapped1", "doublewrapped", "gareth1", "badsetupCR", "badsetupLF", "vertwrap", "tabwrap", "multiCase", "UPPERCASE", "0dwrap", "0dspam", "connection", "spjunk", "backslash", "nel", "nbsp", "shy", "shy2", "spaceFF", "unispace", "http1.0", "0dsuffix", "tabsuffix", "commaCow", "cowComma", "contentEnc", "quoted", "aposed", "dualchunk", "lazygrep", "revdualchunk", "nested", "encode", "accentTE", "accentCH", "removed", "get", "options", "head", "range", "qencode", "qencodeutf", "badwrap", "bodysplit", "h1case", "CL-dualCL", "CL-plus", "CL-minus", "CL-pad", "CL-bigpad", "CL-spacepad", "CL-e", "CL-dec", "CL-commaprefix", "CL-commasuffix", "CL-expect", "CL-expect-obfs", "CL-error"}

func Techniques() []string {
	out := append([]string(nil), base...)
	for _, p := range []string{"spacefix1:", "prefix1:", "suffix1:", "namesuffix1:"} {
		for _, c := range special {
			out = append(out, p+strconv.Itoa(int(c)))
		}
	}
	return out
}
func replaceAll(in, old, n []byte) []byte   { return bytes.Replace(in, old, n, -1) }
func replaceFirst(in, old, n []byte) []byte { return bytes.Replace(in, old, n, 1) }
func headerValue(r []byte, name string) []byte {
	prefix := []byte(name + ": ")
	i := bytes.Index(r, prefix)
	if i < 0 {
		return nil
	}
	s := r[i+len(prefix):]
	if e := bytes.IndexAny(s, "\r\n"); e >= 0 {
		s = s[:e]
	}
	return s
}
func addHeader(r []byte, line string) []byte {
	i := bytes.Index(r, []byte("\r\n\r\n"))
	if i < 0 {
		return r
	}
	out := append([]byte(nil), r[:i]...)
	out = append(out, []byte("\r\n"+line)...)
	return append(out, r[i:]...)
}
func Apply(r []byte, name, tech string) ([]byte, error) {
	if name != "Content-Length" && name != "Transfer-Encoding" {
		return nil, errors.New("unsupported target header")
	}
	h := []byte(name + ": ")
	value := headerValue(r, name)
	if name == "Transfer-Encoding" {
		value = []byte("chunked")
	}
	original := append([]byte(nil), r...)
	out := original
	var p []byte
	switch tech {
	case "vanilla":
		return original, nil
	case "underjoin1":
		p = bytes.ReplaceAll(h, []byte("-"), []byte("_"))
	case "spacejoin1":
		p = bytes.ReplaceAll(h, []byte("-"), []byte(" "))
	case "space1":
		p = bytes.ReplaceAll(h, []byte(":"), []byte(" :"))
	case "nameprefix1":
		p = append([]byte("Foo: bar\r\n "), h...)
	case "nameprefix2":
		p = append([]byte("Foo: bar\r\n\t"), h...)
	case "valueprefix1":
		p = append(h, ' ')
	case "nospace1":
		p = bytes.ReplaceAll(h, []byte(" "), nil)
	case "linewrapped1":
		p = bytes.ReplaceAll(h, []byte(" "), []byte("\n "))
	case "doublewrapped":
		p = bytes.ReplaceAll(h, []byte(" "), []byte("\r\n \r\n "))
	case "gareth1":
		p = bytes.ReplaceAll(h, []byte(":"), []byte("\n :"))
	case "badsetupCR":
		p = append([]byte("Foo: bar\r"), h...)
	case "badsetupLF":
		p = append([]byte("Foo: bar\n"), h...)
	case "vertwrap":
		p = append(h, []byte("\n\v")...)
	case "tabwrap":
		p = append(h, []byte("\r\n\t")...)
	case "UPPERCASE":
		p = bytes.ToUpper(h)
	case "multiCase":
		p = bytes.ToUpper(h)
		p[0] += 32
	case "connection":
		p = []byte("Connection: " + name + "\r\n" + string(h))
	case "spjunk":
		p = bytes.ReplaceAll(h, []byte(":"), []byte(" x:"))
	case "backslash":
		p = bytes.ReplaceAll(h, []byte("-"), []byte("\\"))
	case "nel":
		p = bytes.ReplaceAll(h, []byte(":"), []byte("\xc2\x85:"))
	case "nbsp":
		p = bytes.ReplaceAll(h, []byte(":"), []byte("\xc2\xa0:"))
	case "shy":
		p = bytes.ReplaceAll(h, []byte("-"), []byte("\xc2\xad"))
	case "shy2":
		p = bytes.ReplaceAll(h, []byte(":"), []byte("\xc2\xad:"))
	case "spaceFF":
		p = append(append([]byte{}, h[:len(h)-1]...), 0xff)
	case "unispace":
		p = append(append([]byte{}, h[:len(h)-1]...), 0xa0)
	}
	if p != nil {
		out = replaceAll(out, h, p)
	}
	for _, prefix := range []string{"spacefix1:", "prefix1:", "namesuffix1:"} {
		if strings.HasPrefix(tech, prefix) {
			n, e := strconv.Atoi(strings.TrimPrefix(tech, prefix))
			if e != nil || n < 0 || n > 255 {
				return nil, errors.New("invalid technique byte")
			}
			c := byte(n)
			switch prefix {
			case "spacefix1:":
				p = append(bytes.ReplaceAll(h, []byte(" "), nil), c)
			case "prefix1:":
				p = append(append([]byte{}, h...), c)
			case "namesuffix1:":
				p = bytes.ReplaceAll(h, []byte(":"), []byte{c, ':'})
			}
			out = replaceAll(original, h, p)
		}
	}
	full := append(append([]byte{}, h...), value...)
	switch tech {
	case "http1.0":
		out = replaceFirst(out, []byte("HTTP/1.1"), []byte("HTTP/1.0"))
		out = replaceFirst(out, []byte("HTTP/2"), []byte("HTTP/1.0"))
	case "0dsuffix":
		out = replaceAll(original, full, append(full, '\r'))
	case "tabsuffix":
		out = replaceAll(original, full, append(full, '\t'))
	case "removed":
		out = replaceAll(original, full, []byte("Nothing-interesting: 1"))
	case "get", "options", "head":
		i := bytes.IndexByte(original, ' ')
		if i > 0 {
			out = append([]byte(strings.ToUpper(tech)), original[i:]...)
		}
	case "range":
		out = addHeader(original, "Range: bytes=0-0")
	}
	if name == "Transfer-Encoding" {
		repl := map[string]string{"commaCow": "Transfer-Encoding: chunked, identity", "cowComma": "Transfer-Encoding: identity, chunked", "contentEnc": "Content-Encoding: chunked", "quoted": "Transfer-Encoding: \"chunked\"", "aposed": "Transfer-Encoding: 'chunked'", "lazygrep": "Transfer-Encoding: chunk", "revdualchunk": "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked", "nested": "Transfer-Encoding: identity, chunked, identity", "encode": "Transfer-%45ncoding: chunked", "qencode": "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=", "qencodeutf": "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?="}
		if x, ok := repl[tech]; ok {
			out = replaceAll(original, []byte("Transfer-Encoding: chunked"), []byte(x))
		}
		if tech == "dualchunk" {
			out = addHeader(original, "Transfer-encoding: identity")
		}
		if tech == "h1case" {
			out = replaceAll(original, full, append(bytes.ToUpper(h), value...))
		}
		if tech == "accentTE" {
			out = replaceAll(original, h, []byte{'T', 'r', 'a', 'n', 's', 'f', 0x82, 'r', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' '})
		}
		if tech == "accentCH" {
			out = replaceAll(original, []byte("Transfer-Encoding: chu"), append([]byte("Transfer-Encoding: ch"), 0x96))
		}
	}
	if name == "Content-Length" {
		repl := map[string]string{"CL-plus": "Content-Length: +", "CL-minus": "Content-Length: -", "CL-pad": "Content-Length: 0", "CL-bigpad": "Content-Length: 00000000000", "CL-spacepad": "Content-Length: 0 ", "CL-commaprefix": "Content-Length: 0, "}
		if x, ok := repl[tech]; ok {
			out = replaceAll(original, h, []byte(x))
		}
		suffix := map[string]string{"CL-e": "e0", "CL-dec": ".0", "CL-commasuffix": ", 0"}
		if x, ok := suffix[tech]; ok {
			out = replaceAll(original, full, append(full, []byte(x)...))
		}
		if tech == "CL-dualCL" {
			out = replaceAll(original, full, []byte(fmt.Sprintf("Content-Length: %s\r\nContent-Length: %s", value, value)))
		}
		if tech == "CL-expect" {
			out = addHeader(original, "Expect: 100-continue")
		}
		if tech == "CL-expect-obfs" {
			out = addHeader(original, "Expect: x 100-continue")
		}
		if tech == "CL-error" {
			out = replaceAll(original, full, append([]byte("X-Invalid Y: \r\n"), full...))
		}
	}
	if bytes.Equal(out, original) && tech != "vanilla" {
		return nil, fmt.Errorf("technique %q had no effect", tech)
	}
	return out, nil
}
