package xmldsig

import (
	"slices"
	"strings"
)

// Exclusive XML Canonicalization 1.0 without comments
// (http://www.w3.org/2001/10/xml-exc-c14n#), for the node sets XMLDSig
// references produce here: a whole document or one element's subtree,
// each possibly without one excluded element (the enveloped signature).
// No InclusiveNamespaces prefix list.

// CanonicalizeDocument canonicalizes the document node set without comments and
// without the subtree of exclude (enveloped-signature transform).
func CanonicalizeDocument(doc *Document, exclude *Element) []byte {
	var b strings.Builder
	for _, n := range doc.Before {
		if pi, ok := n.(ProcInst); ok {
			writePI(&b, pi)
			b.WriteByte('\n')
		}
	}
	canonElement(&b, doc.Root, nil, exclude)
	for _, n := range doc.After {
		if pi, ok := n.(ProcInst); ok {
			b.WriteByte('\n')
			writePI(&b, pi)
		}
	}
	return []byte(b.String())
}

// CanonicalizeSubtree canonicalizes the subtree of e (an element node set whose
// apex is e).
func CanonicalizeSubtree(e, exclude *Element) []byte {
	var b strings.Builder
	canonElement(&b, e, nil, exclude)
	return []byte(b.String())
}

// rendered maps prefixes to the namespace declarations in effect in the
// output for the nearest output ancestor; "" is the default namespace.
type rendered map[string]string

func canonElement(b *strings.Builder, e *Element, outer rendered, exclude *Element) {
	if e == exclude {
		return
	}
	// Visibly utilized prefixes: the element's own, and those of its
	// qualified attributes (exc-c14n Section 3).
	used := []string{e.Prefix}
	for _, a := range e.Attrs {
		if a.Prefix != "" && a.Prefix != "xml" && !slices.Contains(used, a.Prefix) {
			used = append(used, a.Prefix)
		}
	}
	var decls []nsDecl
	inner := outer
	copied := false
	for _, p := range used {
		if p == "xml" {
			continue
		}
		uri, _ := e.Lookup(p)
		prev, ok := outer[p]
		if !ok {
			prev = ""
		}
		if p == "" && uri == "" && prev == "" {
			continue
		}
		if ok && prev == uri || !ok && p == "" && uri == "" {
			continue
		}
		decls = append(decls, nsDecl{p, uri})
		if !copied {
			inner = make(rendered, len(outer)+len(used))
			for k, v := range outer {
				inner[k] = v
			}
			copied = true
		}
		inner[p] = uri
	}
	// The default namespace declaration sorts first, then by prefix.
	slices.SortFunc(decls, func(x, y nsDecl) int { return strings.Compare(x.Prefix, y.Prefix) })
	attrs := slices.Clone(e.Attrs)
	for i := range attrs {
		if attrs[i].Prefix == "xml" {
			attrs[i].Space = NSXML
		}
	}
	slices.SortFunc(attrs, func(x, y Attr) int {
		if c := strings.Compare(x.Space, y.Space); c != 0 {
			return c
		}
		return strings.Compare(x.Local, y.Local)
	})

	b.WriteByte('<')
	b.WriteString(e.Name())
	for _, d := range decls {
		if d.Prefix == "" {
			b.WriteString(` xmlns="`)
		} else {
			b.WriteString(" xmlns:")
			b.WriteString(d.Prefix)
			b.WriteString(`="`)
		}
		escapeAttr(b, d.uri)
		b.WriteByte('"')
	}
	for _, a := range attrs {
		b.WriteByte(' ')
		if a.Prefix != "" {
			b.WriteString(a.Prefix)
			b.WriteByte(':')
		}
		b.WriteString(a.Local)
		b.WriteString(`="`)
		escapeAttr(b, a.Value)
		b.WriteByte('"')
	}
	b.WriteByte('>')
	for _, k := range e.Kids {
		switch k := k.(type) {
		case *Element:
			canonElement(b, k, inner, exclude)
		case Text:
			escapeText(b, string(k))
		case ProcInst:
			writePI(b, k)
		}
	}
	b.WriteString("</")
	b.WriteString(e.Name())
	b.WriteByte('>')
}

func writePI(b *strings.Builder, pi ProcInst) {
	b.WriteString("<?")
	b.WriteString(pi.Target)
	if inst := strings.TrimLeft(pi.Inst, " \t\r\n"); inst != "" {
		b.WriteByte(' ')
		b.WriteString(inst)
	}
	b.WriteString("?>")
}

func escapeText(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
}

func escapeAttr(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
}
