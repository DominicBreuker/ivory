package xmldsig

import (
	"bytes"
	"testing"
)

// FuzzCanonicalize parses arbitrary documents and canonicalizes them.
// Parse and the canonicalization must never panic, and canonicalization
// is idempotent: the canonical form parses and canonicalizes to itself.
func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{
		`<a b="1" a="2"/>`,
		`<a xmlns="urn:x" xmlns:p="urn:p"><p:b p:c="1" d="2"><c xmlns=""/></p:b></a>`,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- c --><?pi x?><a xml:lang=\"de\">&lt;&amp;&gt;<![CDATA[x]]>\r\n</a><?pi y?>",
		`<r xmlns="urn:d" xmlns:ds="urn:ds"><ds:S Id="s"><ds:I a="&quot;"><x/></ds:I></ds:S></r>`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Parse(data)
		if err != nil {
			return
		}
		c := CanonicalizeDocument(doc, nil)
		doc2, err := Parse(c)
		if err != nil {
			t.Fatalf("canonical form doesn't parse: %v\n%s", err, c)
		}
		if c2 := CanonicalizeDocument(doc2, nil); !bytes.Equal(c, c2) {
			t.Fatalf("not idempotent:\n%s\n%s", c, c2)
		}
		for _, e := range doc.IDs {
			CanonicalizeSubtree(e, nil)
		}
		if s, err := FindSignature(doc); err == nil {
			s.VerifyReferences(doc)
		}
	})
}
