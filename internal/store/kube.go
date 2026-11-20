// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// kubeClustersSchema is the schema version whose migration (00008) added the
// kube_clusters table. A newer binary runs on an older cluster database until
// `hearth cluster migrate`; before this version no cluster can be added.
const kubeClustersSchema = 8

// KubeCluster is a Kubernetes cluster adopted through a kubeconfig.
type KubeCluster struct {
	ID   string
	Name string
	// Sealed is the encrypted kubeconfig. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddKubeCluster stores a cluster and its sealed kubeconfig. A duplicate ID
// or name is a constraint violation.
type AddKubeCluster struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddKubeCluster) Op() string { return "add_kube_cluster" }

func (AddKubeCluster) minSchema() int64 { return kubeClustersSchema }

func (c AddKubeCluster) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "kube_clusters", row{
		"id": c.ID, "name": c.Name, "kubeconfig": c.Sealed, "created_at": c.CreatedAt,
	})
}

// RemoveKubeCluster deletes a cluster. It fails with ErrNotFound if there is
// none with ID.
type RemoveKubeCluster struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveKubeCluster) Op() string { return "remove_kube_cluster" }

func (RemoveKubeCluster) minSchema() int64 { return kubeClustersSchema }

func (c RemoveKubeCluster) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "kube_clusters", c.ID)
}

// KubeClusters is the repository for adopted Kubernetes clusters.
type KubeClusters struct{ s *Store }

// KubeClusters returns the Kubernetes cluster repository.
func (s *Store) KubeClusters() KubeClusters { return KubeClusters{s: s} }

// Add stores c. Its kubeconfig must already be sealed.
func (r KubeClusters) Add(ctx context.Context, c KubeCluster) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add kube cluster: ID, name and sealed kubeconfig are required")
	}
	if _, err := r.s.apply(ctx, AddKubeCluster{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add kube cluster %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes cluster id, or fails with ErrNotFound.
func (r KubeClusters) Remove(ctx context.Context, id string) error {
	if _, err := r.s.apply(ctx, RemoveKubeCluster{ID: id}); err != nil {
		return fmt.Errorf("remove kube cluster %s: %w", id, err)
	}
	return nil
}

// List returns every cluster ordered by name. Before the schema that added
// them there are none.
func (r KubeClusters) List(ctx context.Context) ([]KubeCluster, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list kube clusters: %w", err)
	}
	if v < kubeClustersSchema {
		return nil, nil
	}
	q := `SELECT id, name, kubeconfig, created_at FROM kube_clusters ORDER BY name`
	if v >= VersionedSchema {
		q = `SELECT id, name, kubeconfig, created_at FROM kube_clusters WHERE _deleted = 0 ORDER BY name`
	}
	rows, err := r.s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list kube clusters: %w", err)
	}
	defer rows.Close()
	var out []KubeCluster
	for rows.Next() {
		var (
			c  KubeCluster
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list kube clusters: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list kube clusters: %w", err)
	}
	return out, nil
}
