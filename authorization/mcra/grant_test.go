package mcra

import (
	"slices"
	"testing"

	mcrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
)

func TestGrantIndexFrom(t *testing.T) {
	t.Parallel()

	app := placementRef{namespace: "sets", name: "app"}
	plat := placementRef{namespace: "sets", name: "plat"}
	extra := placementRef{namespace: "other", name: "extra"}
	byPlacement := map[placementRef]clusterSet{
		app:   newClusterSet([]string{"cluster-b", "cluster-a"}),
		plat:  newClusterSet([]string{"cluster-z"}),
		extra: newClusterSet([]string{"cluster-b", "cluster-c"}),
	}

	t.Run("user", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{app}},
		}, byPlacement)
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b")
		assertClusters(t, idx, "bob", nil)
	})

	t.Run("group", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindGroup, name: "eng"}, placements: []placementRef{plat}},
		}, byPlacement)
		assertClusters(t, idx, "zoe", []string{"eng"}, "cluster-z")
		assertClusters(t, idx, "zoe", nil)
		assertClusters(t, idx, "zoe", []string{""})
	})

	t.Run("user and group", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{app}},
			{subject: subjectRef{kind: subjectKindGroup, name: "eng"}, placements: []placementRef{plat}},
		}, byPlacement)
		assertClusters(t, idx, "alice", []string{"eng"}, "cluster-a", "cluster-b", "cluster-z")
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b")
		assertClusters(t, idx, "zoe", []string{"eng"}, "cluster-z")
	})

	t.Run("two assignments", func(t *testing.T) {
		items := []mcrav1beta1.MulticlusterRoleAssignment{
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "app")),
			),
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
				roleAssignment("admin", clusterSelectionPlacements, place("other", "extra")),
			),
		}
		idx := grantIndexFrom(parsedAssignments(items), byPlacement)
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b", "cluster-c")
	})

	t.Run("service account", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{
				subject:    subjectRef{kind: subjectKindServiceAccount, namespace: "team", name: "bot"},
				placements: []placementRef{app},
			},
			{
				subject:    subjectRef{kind: subjectKindServiceAccount, namespace: "other", name: "bot"},
				placements: []placementRef{plat},
			},
		}, byPlacement)
		assertClusters(t, idx, "system:serviceaccount:team:bot", nil, "cluster-a", "cluster-b")
		assertClusters(t, idx, "system:serviceaccount:other:bot", nil, "cluster-z")
		assertClusters(t, idx, "system:serviceaccount:team:other", nil)
		assertClusters(t, idx, "system:serviceaccount:team:bot:extra", nil)
		assertClusters(t, idx, "system:serviceaccount:team", nil)
		assertClusters(t, idx, "carol", []string{"system:serviceaccounts"})
		assertClusters(t, idx, "system:serviceaccount:team:bot", []string{"system:serviceaccounts"}, "cluster-a", "cluster-b")
	})

	t.Run("empty cluster name", func(t *testing.T) {
		decisions := []clusterv1beta1.PlacementDecision{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "sets",
					Labels:    map[string]string{clusterv1beta1.PlacementLabel: "app"},
				},
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: ""},
						{ClusterName: "cluster-a"},
					},
				},
			},
		}
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{app}},
		}, clustersByPlacement(decisions))
		got := idx.clusters("alice", nil)
		if got.has("") || !slices.Equal(got.names, []string{"cluster-a"}) {
			t.Fatalf("clusters = %#v", got.names)
		}
	})

	t.Run("unknown kind", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{app}},
			{subject: subjectRef{kind: "Robot", name: "alice"}, placements: []placementRef{plat}},
		}, byPlacement)
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b")
	})

	t.Run("placements type only", func(t *testing.T) {
		items := []mcrav1beta1.MulticlusterRoleAssignment{
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "app")),
				roleAssignment("edit", "manual", place("sets", "plat")),
			),
		}
		idx := grantIndexFrom(parsedAssignments(items), byPlacement)
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b")
	})

	t.Run("duplicate clusters", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{app, extra}},
			{subject: subjectRef{kind: subjectKindGroup, name: "eng"}, placements: []placementRef{app}},
		}, byPlacement)
		got := idx.clusters("alice", []string{"eng"})
		if !slices.Equal(got.names, []string{"cluster-a", "cluster-b", "cluster-c"}) {
			t.Fatalf("clusters = %#v", got.names)
		}
	})

	t.Run("missing placement", func(t *testing.T) {
		idx := grantIndexFrom([]parsedAssignment{
			{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{{namespace: "sets", name: "missing"}}},
		}, byPlacement)
		assertClusters(t, idx, "alice", nil)
	})
}

func assertClusters(t *testing.T, idx grantIndex, user string, groups []string, want ...string) {
	t.Helper()
	got := idx.clusters(user, groups)
	if !slices.Equal(got.names, want) {
		t.Fatalf("clusters(%q, %#v) = %#v, want %#v", user, groups, got.names, want)
	}
}

func mcraSubject(subject mcrav1beta1.Subject, assignments ...mcrav1beta1.RoleAssignment) mcrav1beta1.MulticlusterRoleAssignment {
	return mcrav1beta1.MulticlusterRoleAssignment{
		Spec: mcrav1beta1.MulticlusterRoleAssignmentSpec{
			Subject:         subject,
			RoleAssignments: assignments,
		},
	}
}

func roleAssignment(role, selType string, refs ...mcrav1beta1.PlacementRef) mcrav1beta1.RoleAssignment {
	return mcrav1beta1.RoleAssignment{
		Name:        role,
		ClusterRole: role,
		ClusterSelection: mcrav1beta1.ClusterSelection{
			Type:       selType,
			Placements: refs,
		},
	}
}

func place(namespace, name string) mcrav1beta1.PlacementRef {
	return mcrav1beta1.PlacementRef{Namespace: namespace, Name: name}
}
