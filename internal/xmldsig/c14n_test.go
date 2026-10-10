package xmldsig

import (
	"bytes"
	"testing"
)

// TestC14N checks exclusive canonicalization against hand-made vectors
// (W3C Exclusive XML Canonicalization 1.0). The canonical forms of real
// TSLs were also compared with those of libxml2: identical.
func TestC14N(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`<a b="1" a="2"/>`, `<a a="2" b="1"></a>`},
		{`<a xmlns="urn:x" xmlns:p="urn:p"><b/></a>`, `<a xmlns="urn:x"><b></b></a>`},
		{`<a xmlns:p="urn:p"><p:b p:c="1" d="2"/></a>`, `<a><p:b xmlns:p="urn:p" d="2" p:c="1"></p:b></a>`},
		{`<a xmlns="urn:x"><b xmlns=""/></a>`, `<a xmlns="urn:x"><b xmlns=""></b></a>`},
		{`<a><b xmlns=""/></a>`, `<a><b></b></a>`},
		{`<p:a xmlns:p="urn:p"><p:b xmlns:p="urn:p"/></p:a>`, `<p:a xmlns:p="urn:p"><p:b></p:b></p:a>`},
		{`<p:a xmlns:p="urn:p"><p:b xmlns:p="urn:q"/></p:a>`, `<p:a xmlns:p="urn:p"><p:b xmlns:p="urn:q"></p:b></p:a>`},
		{`<a q:z="1" xmlns:q="urn:q" xmlns:p="urn:a" p:z="2" z="3"/>`, `<a xmlns:p="urn:a" xmlns:q="urn:q" z="3" p:z="2" q:z="1"></a>`},
		{`<a xml:lang="de">x</a>`, `<a xml:lang="de">x</a>`},
		{"<a>&lt;&amp;&gt;\"'\r\n<![CDATA[<x>]]></a>", "<a>&lt;&amp;&gt;\"'\n&lt;x&gt;</a>"},
		{`<a b="&lt;&amp;&quot;'&gt;"/>`, `<a b="&lt;&amp;&quot;'>"></a>`},
		{`<a><!-- c --><?pi  data ?><?pi2?></a>`, `<a><?pi data ?><?pi2?></a>`},
		{"<?xml version=\"1.0\"?>\n<!-- c -->\n<?pi x?>\n<a/>\n<?pi y?>", "<?pi x?>\n<a></a>\n<?pi y?>"},
		{`<a>&#x20AC;&#xD;</a>`, "<a>€&#xD;</a>"},
	} {
		doc, err := Parse([]byte(tc.in))
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if got := CanonicalizeDocument(doc, nil); !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("%s:\n got %s\nwant %s", tc.in, got, tc.want)
		}
	}
	// A subtree: the apex declares the namespaces it uses from ancestors.
	doc, err := Parse([]byte(`<r xmlns="urn:d" xmlns:ds="urn:ds"><ds:S Id="s"><ds:I a="1"><x/></ds:I></ds:S></r>`))
	if err != nil {
		t.Fatal(err)
	}
	got := CanonicalizeSubtree(doc.IDs["s"].Children()[0], nil)
	if want := `<ds:I xmlns:ds="urn:ds" a="1"><x xmlns="urn:d"></x></ds:I>`; string(got) != want {
		t.Errorf("subtree:\n got %s\nwant %s", got, want)
	}
}
