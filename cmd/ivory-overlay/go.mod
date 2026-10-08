module github.com/DominicBreuker/ivory/cmd/ivory-overlay

// A module of its own, with an old go line and no dependencies, so that any
// installed Go >= 1.22 can build the tool and use it to fetch the pinned
// release. The ivory module itself needs the pinned release.
go 1.22
