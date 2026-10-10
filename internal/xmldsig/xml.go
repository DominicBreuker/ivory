package xmldsig

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A minimal XML tree, enough for exclusive canonicalization (C14N) and for
// reading the TSL. It is built from encoding/xml's raw tokens, so that
// namespace prefixes and declarations stay as they were written.

const (
	NSXML   = "http://www.w3.org/XML/1998/namespace"
	nsXMLNS = "http://www.w3.org/2000/xmlns/"
)

// A Node is an *Element, a Text, a ProcInst or a Comment.
type Node interface{ isNode() }

// An Element is an element with its attributes and children.
type Element struct {
	Prefix, Local string
	// Space is the namespace name of the element, resolved.
	Space  string
	Attrs  []Attr
	nsDecl []nsDecl
	Parent *Element
	Kids   []Node
}

// An Attr is an attribute other than a namespace declaration. Space is
// the resolved namespace name ("" for unqualified attributes).
type Attr struct {
	Prefix, Local, Space, Value string
}

// nsDecl is a namespace declaration: xmlns="uri" (prefix "") or
// xmlns:prefix="uri".
type nsDecl struct {
	Prefix, uri string
}

// A Text is character data.
type Text string

// A ProcInst is a processing instruction.
type ProcInst struct {
	Target string
	Inst   string
}

// A Comment stands for a comment; its content is dropped.
type Comment struct{}

func (*Element) isNode() {}
func (Text) isNode()     {}
func (ProcInst) isNode() {}
func (Comment) isNode()  {}

// A Document is a parsed XML document: the nodes before the root
// element, the root, and the nodes after it (comments and processing
// instructions).
type Document struct {
	Before []Node
	Root   *Element
	After  []Node
	// IDs maps the values of attributes named "Id" to their elements.
	IDs map[string]*Element
}

// maxDepth limits element nesting; the TSL needs about 12 levels.
const maxDepth = 64

// Parse parses data strictly: well-formed, namespace-well-formed, no
// DTD, no undeclared prefixes, no duplicate attributes, no duplicate Id
// values. Attribute values containing tabs, line feeds or carriage returns
// are rejected, because encoding/xml doesn't normalize them as XML 1.0
// Section 3.3.3 requires, and canonicalization would be wrong.
func Parse(data []byte) (*Document, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	d.CharsetReader = nil
	doc := &Document{IDs: make(map[string]*Element)}
	var cur *Element
	depth := 0
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tsl: XML: %w", err)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxDepth {
				return nil, errors.New("tsl: XML nested too deeply")
			}
			if cur == nil && doc.Root != nil {
				return nil, errors.New("tsl: XML: more than one root element")
			}
			e, err := newElement(tok, cur)
			if err != nil {
				return nil, err
			}
			for _, a := range e.Attrs {
				if a.Space == "" && a.Local == "Id" {
					if _, dup := doc.IDs[a.Value]; dup {
						return nil, fmt.Errorf("tsl: XML: duplicate Id %q", a.Value)
					}
					doc.IDs[a.Value] = e
				}
			}
			if cur == nil {
				doc.Root = e
			} else {
				cur.Kids = append(cur.Kids, e)
			}
			cur = e
		case xml.EndElement:
			if cur == nil || tok.Name.Space != cur.Prefix || tok.Name.Local != cur.Local {
				return nil, fmt.Errorf("tsl: XML: unexpected end element %s", tok.Name.Local)
			}
			depth--
			cur = cur.Parent
		case xml.CharData:
			if cur == nil {
				if len(bytes.TrimLeft(tok, " \t\r\n")) != 0 {
					return nil, errors.New("tsl: XML: text outside the root element")
				}
				continue
			}
			if n := len(cur.Kids); n > 0 {
				if t, ok := cur.Kids[n-1].(Text); ok {
					cur.Kids[n-1] = t + Text(tok)
					continue
				}
			}
			cur.Kids = append(cur.Kids, Text(tok))
		case xml.Comment:
			add(doc, cur, Comment{})
		case xml.ProcInst:
			if tok.Target == "xml" {
				if cur != nil || doc.Root != nil || len(doc.Before) != 0 {
					return nil, errors.New("tsl: XML: misplaced XML declaration")
				}
				if err := checkDeclaration(string(tok.Inst)); err != nil {
					return nil, err
				}
				continue
			}
			if strings.EqualFold(tok.Target, "xml") {
				return nil, errors.New("tsl: XML: reserved processing instruction target")
			}
			add(doc, cur, ProcInst{tok.Target, string(tok.Inst)})
		case xml.Directive:
			return nil, errors.New("tsl: XML: DTDs and other directives are not allowed")
		}
	}
	if doc.Root == nil || cur != nil {
		return nil, errors.New("tsl: XML: no complete root element")
	}
	return doc, nil
}

// checkDeclaration accepts only UTF-8 documents.
func checkDeclaration(inst string) error {
	i := strings.Index(inst, "encoding=")
	if i < 0 {
		return nil
	}
	v := inst[i+len("encoding="):]
	if len(v) < 2 {
		return errors.New("tsl: XML: malformed declaration")
	}
	q := v[0]
	end := strings.IndexByte(v[1:], q)
	if (q != '"' && q != '\'') || end < 0 {
		return errors.New("tsl: XML: malformed declaration")
	}
	if enc := v[1 : 1+end]; !strings.EqualFold(enc, "UTF-8") {
		return fmt.Errorf("tsl: XML: unsupported encoding %q", enc)
	}
	return nil
}

func add(doc *Document, cur *Element, n Node) {
	switch {
	case cur != nil:
		cur.Kids = append(cur.Kids, n)
	case doc.Root == nil:
		doc.Before = append(doc.Before, n)
	default:
		doc.After = append(doc.After, n)
	}
}

func newElement(tok xml.StartElement, parent *Element) (*Element, error) {
	e := &Element{Prefix: tok.Name.Space, Local: tok.Name.Local, Parent: parent}
	if e.Local == "" || strings.Contains(e.Local, ":") {
		return nil, fmt.Errorf("tsl: XML: bad element name %q", tok.Name.Local)
	}
	for _, a := range tok.Attr {
		switch {
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			if a.Value == NSXML || a.Value == nsXMLNS {
				return nil, errors.New("tsl: XML: reserved namespace as default namespace")
			}
			e.nsDecl = append(e.nsDecl, nsDecl{"", a.Value})
		case a.Name.Space == "xmlns":
			if a.Value == "" || a.Name.Local == "xmlns" || a.Name.Local == "xml" && a.Value != NSXML ||
				a.Name.Local != "xml" && (a.Value == NSXML || a.Value == nsXMLNS) {
				return nil, fmt.Errorf("tsl: XML: bad declaration of prefix %q", a.Name.Local)
			}
			e.nsDecl = append(e.nsDecl, nsDecl{a.Name.Local, a.Value})
		default:
			if strings.ContainsAny(a.Value, "\t\n\r") {
				return nil, fmt.Errorf("tsl: XML: attribute %s contains a tab or line break", a.Name.Local)
			}
			e.Attrs = append(e.Attrs, Attr{Prefix: a.Name.Space, Local: a.Name.Local, Value: a.Value})
		}
	}
	for i, d := range e.nsDecl {
		for _, o := range e.nsDecl[:i] {
			if o.Prefix == d.Prefix {
				return nil, fmt.Errorf("tsl: XML: prefix %q declared twice", d.Prefix)
			}
		}
	}
	var ok bool
	if e.Space, ok = e.Lookup(e.Prefix); !ok {
		return nil, fmt.Errorf("tsl: XML: undeclared prefix %q", e.Prefix)
	}
	for i := range e.Attrs {
		a := &e.Attrs[i]
		if a.Prefix != "" {
			if a.Space, ok = e.Lookup(a.Prefix); !ok {
				return nil, fmt.Errorf("tsl: XML: undeclared prefix %q", a.Prefix)
			}
		}
		for _, o := range e.Attrs[:i] {
			if o.Local == a.Local && o.Space == a.Space {
				return nil, fmt.Errorf("tsl: XML: duplicate attribute %s", a.Local)
			}
		}
	}
	return e, nil
}

// Lookup returns the namespace name bound to prefix in e's scope. The
// empty prefix stands for the default namespace, which may be empty.
func (e *Element) Lookup(prefix string) (string, bool) {
	if prefix == "xml" {
		return NSXML, true
	}
	for x := e; x != nil; x = x.Parent {
		for _, d := range x.nsDecl {
			if d.Prefix == prefix {
				return d.uri, true
			}
		}
	}
	return "", prefix == ""
}

// Attr returns the value of the unqualified attribute name.
func (e *Element) Attr(name string) (string, bool) {
	for _, a := range e.Attrs {
		if a.Space == "" && a.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// Children returns the child elements of e.
func (e *Element) Children() []*Element {
	var out []*Element
	for _, k := range e.Kids {
		if c, ok := k.(*Element); ok {
			out = append(out, c)
		}
	}
	return out
}

// Child returns the first child element of e with the given name, or nil.
func (e *Element) Child(space, local string) *Element {
	for _, k := range e.Kids {
		if c, ok := k.(*Element); ok && c.Space == space && c.Local == local {
			return c
		}
	}
	return nil
}

// Text returns the concatenated text content of e's direct children.
func (e *Element) Text() string {
	var b strings.Builder
	for _, k := range e.Kids {
		if t, ok := k.(Text); ok {
			b.WriteString(string(t))
		}
	}
	return b.String()
}

func (e *Element) Is(space, local string) bool {
	return e != nil && e.Space == space && e.Local == local
}

func (e *Element) Name() string {
	if e.Prefix == "" {
		return e.Local
	}
	return e.Prefix + ":" + e.Local
}
