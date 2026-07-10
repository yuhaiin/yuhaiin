package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"fmt"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/api"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

// MigrateLegacySubscriptions rewrites the shared subscriptions table from
// legacy Link JSON (whose type is an enum number) to contract Link JSON.
func MigrateLegacySubscriptions(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_subscriptions_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT name, data_json FROM subscriptions ORDER BY name`)
	if err != nil {
		return fmt.Errorf("query legacy subscriptions failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan legacy subscription failed: %w", err)
		}
		var legacyLink schemanode.Link
		if err := json.Unmarshal([]byte(dataJSON), &legacyLink); err != nil {
			return fmt.Errorf("decode legacy subscription %q failed: %w", name, err)
		}
		link := contractsubscription.Link{
			Name: firstNonEmpty(legacyLink.GetName(), name),
			URL:  legacyLink.GetUrl(),
			Type: legacyLink.GetType().String(),
		}
		data, err := json.Marshal(link)
		if err != nil {
			return fmt.Errorf("encode contract subscription %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE subscriptions
			SET updated_at = ?, data_json = ?
			WHERE name = ?
		`, updatedAt, string(data), name); err != nil {
			return fmt.Errorf("update contract subscription %q failed: %w", name, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy subscriptions failed: %w", err)
	}
	if err := markMigrationDone(ctx, tx, "plain_subscriptions_migration_done"); err != nil {
		return fmt.Errorf("mark subscription migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subscription migration failed: %w", err)
	}
	return nil
}

func ConvertLegacyLinks(in *schemaapi.GetLinksResp) contractsubscription.LinkList {
	var out contractsubscription.LinkList
	if in == nil {
		return out
	}
	out.Items = make([]contractsubscription.Link, 0, len(in.Links))
	for name, link := range in.Links {
		if link == nil {
			continue
		}
		out.Items = append(out.Items, contractsubscription.Link{
			Name: firstNonEmpty(link.GetName(), name),
			URL:  link.GetUrl(),
			Type: link.GetType().String(),
		})
	}
	return out
}

func ConvertContractLinks(in []contractsubscription.Link) []*schemanode.Link {
	out := make([]*schemanode.Link, 0, len(in))
	for _, link := range in {
		typ := schemanode.Type_reserve
		if v, ok := schemanode.Type_value[link.Type]; ok {
			typ = schemanode.Type(v)
		}
		out = append(out, &schemanode.Link{
			Name: link.Name,
			Url:  link.URL,
			Type: typ,
		})
	}
	return out
}

func ConvertLegacyPublishes(in *schemaapi.ListPublishResponse) contractsubscription.PublishList {
	var out contractsubscription.PublishList
	if in == nil {
		return out
	}
	out.Items = make([]contractsubscription.Publish, 0, len(in.Publishes))
	for name, publish := range in.Publishes {
		if publish == nil {
			continue
		}
		out.Items = append(out.Items, ConvertLegacyPublish(firstNonEmpty(publish.GetName(), name), publish))
	}
	return out
}

func ConvertLegacyPublish(name string, in *schemanode.Publish) contractsubscription.Publish {
	if in == nil {
		return contractsubscription.Publish{Name: name}
	}
	return contractsubscription.Publish{
		Name:     firstNonEmpty(in.GetName(), name),
		Points:   in.GetPoints(),
		Path:     in.GetPath(),
		Password: in.GetPassword(),
		Address:  in.GetAddress(),
		Insecure: in.GetInsecure(),
	}
}

func ConvertContractPublish(in contractsubscription.Publish) *schemanode.Publish {
	return &schemanode.Publish{
		Name:     in.Name,
		Points:   in.Points,
		Path:     in.Path,
		Password: in.Password,
		Address:  in.Address,
		Insecure: in.Insecure,
	}
}

func ConvertLegacyPublishResponse(in *schemaapi.PublishResponse) contractsubscription.ResolvePublishResponse {
	var out contractsubscription.ResolvePublishResponse
	if in == nil {
		return out
	}
	out.Points = make([]contractnode.Node, 0, len(in.GetPoints()))
	for _, point := range in.GetPoints() {
		node, _, err := ConvertLegacyNode(point)
		if err == nil {
			out.Points = append(out.Points, node)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
