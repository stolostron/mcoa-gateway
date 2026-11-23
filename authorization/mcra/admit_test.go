package mcra

import (
	"errors"
	"slices"
	"testing"
)

func TestClusterSet(t *testing.T) {
	t.Parallel()

	in := []string{"b", "", "a", "b", "*"}
	set := newClusterSet(in)
	in[0] = "changed"

	if set.len() != 3 {
		t.Fatalf("len = %d, want 3", set.len())
	}
	for _, name := range []string{"a", "b", "*"} {
		if !set.has(name) {
			t.Fatalf("set missing %q", name)
		}
	}
	if set.has("B") || set.has("") || set.has("c") {
		t.Fatal("set admitted a name it does not contain")
	}
	zero := clusterSet{}
	if zero.has("a") || zero.len() != 0 {
		t.Fatal("zero clusterSet admitted a name")
	}
	if newClusterSet([]string{"", ""}).len() != 0 {
		t.Fatal("empty names produced a non-empty set")
	}
}

func TestSplitTenant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want []string
	}{
		{raw: "", want: nil},
		{raw: "   ", want: nil},
		{raw: "cluster-a", want: []string{"cluster-a"}},
		{raw: " cluster-a | cluster-b ", want: []string{"cluster-a", "cluster-b"}},
		{raw: "a||b|", want: []string{"a", "b"}},
		{raw: "b|a|b", want: []string{"b", "a", "b"}},
	}
	for _, tt := range tests {
		got := splitTenant(tt.raw)
		if !slices.Equal(got, tt.want) {
			t.Errorf("splitTenant(%q) = %#v, want %#v", tt.raw, got, tt.want)
		}
	}
}

func TestDerive(t *testing.T) {
	t.Parallel()

	set := newClusterSet([]string{"b", "a.b", "a", "a"})
	if set.joined() != "a|a.b|b" {
		t.Fatalf("joined = %q", set.joined())
	}
	got, err := derive(set, 10)
	if err != nil || got.String() != "a|a.b|b" {
		t.Fatalf("derive = %q, %v", got, err)
	}

	dotted, err := derive(newClusterSet([]string{"cluster.a"}), 10)
	if err != nil || dotted.String() != "cluster.a" {
		t.Fatalf("dotted = %q, %v", dotted, err)
	}

	empty, err := derive(clusterSet{}, 10)
	if !errors.Is(err, errNoClusters) || empty.String() != "" {
		t.Fatalf("empty = %q, %v", empty, err)
	}
	if _, err := derive(newClusterSet([]string{"", ""}), 10); !errors.Is(err, errNoClusters) {
		t.Fatalf("blank names err = %v", err)
	}

	truncated, err := derive(newClusterSet([]string{"c", "b", "a"}), 2)
	var tooMany *tooManyTenantsError
	if !errors.As(err, &tooMany) || tooMany.max != 2 || tooMany.n != 3 || truncated.String() != "" {
		t.Fatalf("over max = %q, %#v, %v", truncated, tooMany, err)
	}
	if tooMany.Error() != "too many tenants: 3 (max 2)" {
		t.Fatalf("error = %q", tooMany.Error())
	}
}

func TestAdmit(t *testing.T) {
	t.Parallel()

	allowed := newClusterSet([]string{"cluster-a", "cluster-b", "cluster-c", "*"})

	tests := []struct {
		name      string
		requested []string
		allowed   clusterSet
		want      string
		ok        bool
	}{
		{name: "empty request", requested: nil, allowed: allowed},
		{name: "empty allow", requested: []string{"cluster-a"}, allowed: clusterSet{}},
		{name: "no overlap", requested: []string{"cluster-x"}, allowed: allowed},
		{name: "one", requested: []string{"cluster-b", "cluster-x"}, allowed: allowed, want: "cluster-b", ok: true},
		{
			name:      "request order",
			requested: []string{"cluster-c", "cluster-a", "cluster-b"},
			allowed:   allowed,
			want:      "cluster-c|cluster-a|cluster-b",
			ok:        true,
		},
		{
			name:      "first occurrence",
			requested: []string{"cluster-a", "cluster-b", "cluster-a"},
			allowed:   allowed,
			want:      "cluster-a|cluster-b",
			ok:        true,
		},
		{
			name:      "does not widen",
			requested: []string{"cluster-a"},
			allowed:   allowed,
			want:      "cluster-a",
			ok:        true,
		},
		{
			name:      "star is a name",
			requested: []string{"other"},
			allowed:   newClusterSet([]string{"*"}),
		},
		{
			name:      "star requested",
			requested: []string{"*"},
			allowed:   allowed,
			want:      "*",
			ok:        true,
		},
		{
			name:      "case sensitive",
			requested: []string{"Cluster-a"},
			allowed:   allowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := admit(tt.requested, tt.allowed)
			if ok != tt.ok || got.String() != tt.want {
				t.Fatalf("admit = %q, %t, want %q, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}
