package mcra

import "strings"

const (
	subjectKindUser            = "User"
	subjectKindGroup           = "Group"
	subjectKindServiceAccount  = "ServiceAccount"
	clusterSelectionPlacements = "placements"

	// serviceAccountPrefix is the Kubernetes username of a ServiceAccount.
	// The namespace and name are the two pieces after this prefix, split on the first colon.
	serviceAccountPrefix = "system:serviceaccount:"
)

// subjectRef is a MulticlusterRoleAssignment subject.
// kind is User, Group, or ServiceAccount.
type subjectRef struct {
	kind      string
	namespace string
	name      string
}

// placementRef is a Placement named by a role assignment.
// Decisions for that Placement live in namespace.
type placementRef struct {
	namespace string
	name      string
}

// parsedAssignment is one subject's placements.
// Cluster role names and target namespaces are already discarded.
type parsedAssignment struct {
	subject    subjectRef
	placements []placementRef
}

// saRef is a ServiceAccount identity. It is not the username string.
type saRef struct {
	namespace string
	name      string
}

// grantIndex is the allow-list for every subject in one hub snapshot.
// The maps are immutable after grantIndexFrom returns.
type grantIndex struct {
	byUser  map[string]clusterSet
	byGroup map[string]clusterSet
	bySA    map[saRef]clusterSet
}

// clusters unions the user's grants, each non-empty group, and a ServiceAccount
// grant when user is system:serviceaccount:<namespace>:<name>.
// The group system:serviceaccounts is an ordinary group name. It is not every ServiceAccount.
func (g grantIndex) clusters(user string, groups []string) clusterSet {
	var names []string
	if set, ok := g.byUser[user]; ok {
		names = append(names, set.names...)
	}
	for _, group := range groups {
		if group == "" {
			continue
		}
		if set, ok := g.byGroup[group]; ok {
			names = append(names, set.names...)
		}
	}
	if namespace, name, ok := serviceAccountUser(user); ok {
		if set, ok := g.bySA[saRef{namespace: namespace, name: name}]; ok {
			names = append(names, set.names...)
		}
	}
	return newClusterSet(names)
}

func serviceAccountUser(user string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(user, serviceAccountPrefix)
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, ":")
	if !found || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
}

// grantIndexFrom unions clusters for each subject.
// A placement ref with no decision set contributes no clusters.
// An unknown subject kind contributes nothing.
func grantIndexFrom(assignments []parsedAssignment, byPlacement map[placementRef]clusterSet) grantIndex {
	users := map[string][]string{}
	groups := map[string][]string{}
	sas := map[saRef][]string{}
	for _, assignment := range assignments {
		names := placementNames(assignment.placements, byPlacement)
		if len(names) == 0 {
			continue
		}
		switch assignment.subject.kind {
		case subjectKindUser:
			if assignment.subject.name == "" {
				continue
			}
			users[assignment.subject.name] = append(users[assignment.subject.name], names...)
		case subjectKindGroup:
			if assignment.subject.name == "" {
				continue
			}
			groups[assignment.subject.name] = append(groups[assignment.subject.name], names...)
		case subjectKindServiceAccount:
			if assignment.subject.namespace == "" || assignment.subject.name == "" {
				continue
			}
			key := saRef{namespace: assignment.subject.namespace, name: assignment.subject.name}
			sas[key] = append(sas[key], names...)
		default:
		}
	}
	return grantIndex{
		byUser:  setsByKey(users),
		byGroup: setsByKey(groups),
		bySA:    setsBySA(sas),
	}
}

func placementNames(refs []placementRef, byPlacement map[placementRef]clusterSet) []string {
	var names []string
	for _, ref := range refs {
		set, ok := byPlacement[ref]
		if !ok {
			continue
		}
		names = append(names, set.names...)
	}
	return names
}

func setsByKey(in map[string][]string) map[string]clusterSet {
	out := make(map[string]clusterSet, len(in))
	for key, names := range in {
		set := newClusterSet(names)
		if set.len() == 0 {
			continue
		}
		out[key] = set
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func setsBySA(in map[saRef][]string) map[saRef]clusterSet {
	out := make(map[saRef]clusterSet, len(in))
	for key, names := range in {
		set := newClusterSet(names)
		if set.len() == 0 {
			continue
		}
		out[key] = set
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
