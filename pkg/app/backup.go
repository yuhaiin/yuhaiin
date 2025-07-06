package app

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gpc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	gpn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Backup struct {
	db       config.DB
	proxy    netapi.Proxy
	instance *AppInstance
	mu       sync.Mutex
	ticker   *time.Ticker
	backup.UnimplementedBackupServer
}

func NewBackup(db config.DB, instance *AppInstance, proxy netapi.Proxy) *Backup {
	b := &Backup{
		db:       db,
		instance: instance,
		proxy:    proxy,
	}

	b.resetTicker()

	return b
}

func (b *Backup) Save(ctx context.Context, opt *backup.BackupOption) (*emptypb.Empty, error) {
	err := b.db.Batch(func(s *pc.Setting) error {
		s.SetBackup(opt)
		return nil
	})
	if err != nil {
		return nil, err
	}

	b.resetTicker()

	return &emptypb.Empty{}, nil
}

func (b *Backup) resetTicker() {
	b.mu.Lock()
	defer b.mu.Unlock()

	opt, err := b.getConfig()
	if err != nil {
		log.Error("get config failed", "err", err)
		return
	}

	if b.ticker != nil {
		b.ticker.Stop()
		b.ticker = nil
	}

	if opt.GetInterval() == 0 {
		return
	}

	b.ticker = time.NewTicker(time.Duration(opt.GetInterval()) * time.Minute)

	log.Info("start new backup ticker", "interval", time.Duration(opt.GetInterval())*time.Minute)

	go func() {
		for range b.ticker.C {
			_, err := b.Backup(context.Background(), &emptypb.Empty{})
			if err != nil {
				log.Error("backup failed", "err", err)
			}
		}
	}()
}

func (b *Backup) Get(context.Context, *emptypb.Empty) (*backup.BackupOption, error) {
	var config *backup.BackupOption
	_ = b.db.Batch(func(s *pc.Setting) error {
		config = s.GetBackup()

		if config == nil {
			config = &backup.BackupOption{}
		}

		if config.GetS3() == nil {
			config.SetS3(backup.S3_builder{
				Enabled:      proto.Bool(false),
				AccessKey:    proto.String(""),
				SecretKey:    proto.String(""),
				Bucket:       proto.String(""),
				EndpointUrl:  proto.String(""),
				Region:       proto.String(""),
				UsePathStyle: proto.Bool(false),
			}.Build())
		}

		if config.GetInstanceName() == "" {
			config.SetInstanceName(uuid.NewString())
		}

		return nil
	})

	return config, nil
}

func calculateHash(content *backup.BackupContent, options *backup.BackupOption) string {
	contentBytes, err := protojson.Marshal(content)
	if err != nil {
		log.Warn("marshal content failed", "err", err)
		return ""
	}

	s3bytes, err := protojson.Marshal(options.GetS3())
	if err != nil {
		log.Warn("marshal s3 failed", "err", err)
		return ""
	}

	hash, err := blake2b.New(32, nil)
	if err != nil {
		log.Warn("new blake2b hash failed", "err", err)
		return ""
	}

	hash.Write(contentBytes)
	hash.Write(s3bytes)
	return hex.EncodeToString(hash.Sum(nil))
}

func (b *Backup) Backup(ctx context.Context, opt *emptypb.Empty) (*emptypb.Empty, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return nil, err
	}

	s3, err := s3.NewS3(backupConfig.GetS3(), b.proxy)
	if err != nil {
		return nil, err
	}

	// node config
	nodes, err := b.instance.Node.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	points := map[string]*point.Point{}

	for _, group := range nodes.GetGroups() {
		for _, node := range group.GetNodesV2() {
			point, err := b.instance.Node.Get(ctx, &wrapperspb.StringValue{Value: node})
			if err != nil {
				return nil, err
			}
			points[node] = point
		}
	}

	subscribes, err := b.instance.Subscribe.Get(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	// resolver config

	dnsServer, err := b.instance.Resolver.Server(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	fakedns, err := b.instance.Resolver.Fakedns(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	hosts, err := b.instance.Resolver.Hosts(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	dnsList, err := b.instance.Resolver.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	dnss := map[string]*dns.Dns{}
	for _, dnsName := range dnsList.GetNames() {
		dns, err := b.instance.Resolver.Get(ctx, &wrapperspb.StringValue{Value: dnsName})
		if err != nil {
			return nil, err
		}
		dnss[dnsName] = dns
	}

	// listener config
	inbounds, err := b.instance.Inbound.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	inboundsMap := map[string]*listener.Inbound{}
	for _, name := range inbounds.GetNames() {
		inbound, err := b.instance.Inbound.Get(ctx, &wrapperspb.StringValue{Value: name})
		if err != nil {
			return nil, err
		}
		inboundsMap[name] = inbound
	}

	// rules config
	ruleConfig, err := b.instance.Rules.Config(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	ruleNames, err := b.instance.Rules.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	var rules []*bypass.Rulev2
	for index, name := range ruleNames.GetNames() {
		rule, err := b.instance.Rules.Get(ctx, gpc.RuleIndex_builder{
			Index: proto.Uint32(uint32(index)),
			Name:  proto.String(name),
		}.Build())
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	listNames, err := b.instance.Lists.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	lists := map[string]*bypass.List{}
	for _, name := range listNames.GetNames() {
		list, err := b.instance.Lists.Get(ctx, &wrapperspb.StringValue{Value: name})
		if err != nil {
			return nil, err
		}

		lists[name] = list
	}

	// tags config
	tags, err := b.instance.Tag.List(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	data := backup.BackupContent_builder{
		Nodes: backup.Nodes_builder{
			Nodes: points,
		}.Build(),
		Subscribes: backup.Subscribes_builder{
			Links: subscribes.GetLinks(),
		}.Build(),
		Dns: dns.DnsConfigV2_builder{
			Server: dns.Server_builder{
				Host: proto.String(dnsServer.GetValue()),
			}.Build(),
			Fakedns:  fakedns,
			Hosts:    hosts.GetHosts(),
			Resolver: dnss,
		}.Build(),
		Inbounds: listener.InboundConfig_builder{
			HijackDns:       proto.Bool(inbounds.GetHijackDns()),
			HijackDnsFakeip: proto.Bool(inbounds.GetHijackDnsFakeip()),
			Sniff:           inbounds.GetSniff(),
			Inbounds:        inboundsMap,
		}.Build(),
		Rules: backup.Rules_builder{
			Config: ruleConfig,
			Rules:  rules,
			Lists:  lists,
		}.Build(),
		Tags: backup.Tags_builder{
			Tags: tags.GetTags(),
		}.Build(),
	}.Build()

	newHash := calculateHash(data, backupConfig)
	if backupConfig.GetLastBackupHash() != "" && backupConfig.GetLastBackupHash() == newHash {
		return &emptypb.Empty{}, nil
	}

	jsonbytes, err := protojson.MarshalOptions{
		Indent: "\t",
	}.Marshal(data)
	if err != nil {
		return nil, err
	}

	if err := s3.Put(ctx, jsonbytes, backupConfig.GetInstanceName()+"-backup.json"); err != nil {
		return nil, err
	}

	if err := b.db.Batch(func(s *pc.Setting) error {
		s.GetBackup().SetLastBackupHash(newHash)
		return nil
	}); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (b *Backup) Restore(ctx context.Context, opt *backup.RestoreOption) (*emptypb.Empty, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return nil, err
	}

	s3, err := s3.NewS3(backupConfig.GetS3(), b.proxy)
	if err != nil {
		return nil, err
	}

	data, err := s3.Get(ctx, backupConfig.GetInstanceName()+"-backup.json")
	if err != nil {
		return nil, err
	}

	var backupContent backup.BackupContent
	if err := protojson.Unmarshal(data, &backupContent); err != nil {
		return nil, err
	}

	if opt.GetAll() {
		opt.SetDns(true)
		opt.SetInbounds(true)
		opt.SetNodes(true)
		opt.SetRules(true)
		opt.SetTags(true)
		opt.SetLists(true)
		opt.SetSubscribes(true)
	}

	if opt.GetDns() {
		if err := b.restoreDns(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetInbounds() {
		if err := b.restoreInbounds(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetNodes() {
		if err := b.restoreNodes(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetRules() {
		if err := b.restoreRules(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetTags() {
		if err := b.restoreTags(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetLists() {
		if err := b.restoreLists(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	if opt.GetSubscribes() {
		if err := b.restoreSubscribes(ctx, &backupContent); err != nil {
			return nil, err
		}
	}

	return &emptypb.Empty{}, nil
}

func (b *Backup) restoreDns(ctx context.Context, content *backup.BackupContent) error {
	if content.GetDns() == nil {
		log.Warn("dns config is empty")
		return nil
	}
	dns := content.GetDns()

	if dns.GetServer().GetHost() != "" {
		_, err := b.instance.Resolver.SaveServer(ctx,
			&wrapperspb.StringValue{Value: dns.GetServer().GetHost()})
		if err != nil {
			return err
		}
	}

	if dns.GetFakedns() != nil {
		_, err := b.instance.Resolver.SaveFakedns(ctx, dns.GetFakedns())
		if err != nil {
			return err
		}
	}

	if dns.GetHosts() != nil {
		_, err := b.instance.Resolver.SaveHosts(ctx, gpc.Hosts_builder{
			Hosts: dns.GetHosts(),
		}.Build())
		if err != nil {
			return err
		}
	}

	if dns.GetResolver() != nil {
		for name, resolver := range dns.GetResolver() {
			_, err := b.instance.Resolver.Save(ctx, gpc.SaveResolver_builder{
				Name:     proto.String(name),
				Resolver: resolver,
			}.Build())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *Backup) restoreInbounds(ctx context.Context, content *backup.BackupContent) error {
	if content.GetInbounds() == nil {
		log.Warn("inbounds config is empty")
		return nil
	}
	inbounds := content.GetInbounds()

	if inbounds.HasHijackDns() || inbounds.HasHijackDnsFakeip() || inbounds.HasSniff() {
		_, err := b.instance.Inbound.Apply(ctx, gpc.InboundsResponse_builder{
			HijackDns:       proto.Bool(inbounds.GetHijackDns()),
			HijackDnsFakeip: proto.Bool(inbounds.GetHijackDnsFakeip()),
			Sniff:           inbounds.GetSniff(),
		}.Build())
		if err != nil {
			return err
		}
	}

	if inbounds.GetInbounds() != nil {
		for name, inbound := range inbounds.GetInbounds() {
			inbound.SetName(name)
			_, err := b.instance.Inbound.Save(ctx, inbound)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *Backup) restoreNodes(ctx context.Context, content *backup.BackupContent) error {
	if content.GetNodes() == nil {
		log.Warn("nodes config is empty")
		return nil
	}
	nodes := content.GetNodes()

	for name, node := range nodes.GetNodes() {
		node.SetName(name)
		_, err := b.instance.Node.Save(ctx, node)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) restoreSubscribes(ctx context.Context, content *backup.BackupContent) error {
	if content.GetSubscribes() == nil {
		log.Warn("subscribes config is empty")
		return nil
	}

	_, err := b.instance.Subscribe.Save(ctx, gpn.SaveLinkReq_builder{
		Links: slices.Collect(maps.Values(content.GetSubscribes().GetLinks())),
	}.Build())
	if err != nil {
		return err
	}

	return nil
}

func (b *Backup) restoreTags(ctx context.Context, content *backup.BackupContent) error {
	if content.GetTags() == nil {
		log.Warn("tags config is empty")
		return nil
	}
	tags := content.GetTags()

	for name, tag := range tags.GetTags() {
		_, err := b.instance.Tag.Save(ctx, gpn.SaveTagReq_builder{
			Tag:  proto.String(name),
			Type: tag.GetType().Enum(),
			Hash: proto.String(tag.GetHash()[0]),
		}.Build())
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) restoreLists(ctx context.Context, content *backup.BackupContent) error {
	if content.GetRules().GetLists() == nil {
		log.Warn("lists config is empty")
		return nil
	}
	lists := content.GetRules().GetLists()

	for name, list := range lists {
		list.SetName(name)
		_, err := b.instance.Lists.Save(ctx, list)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) restoreRules(ctx context.Context, content *backup.BackupContent) error {
	if content.GetRules() == nil {
		log.Warn("rules config is empty")
		return nil
	}
	rules := content.GetRules()

	if rules.HasConfig() {
		_, err := b.instance.Rules.SaveConfig(ctx, rules.GetConfig())
		if err != nil {
			return err
		}
	}

	for _, rule := range rules.GetRules() {
		_, err := b.instance.Rules.Save(ctx, gpc.RuleSaveRequest_builder{
			Rule: rule,
		}.Build())
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) getConfig() (*backup.BackupOption, error) {
	var config *backup.BackupOption
	_ = b.db.Batch(func(s *pc.Setting) error {
		config = s.GetBackup()
		return nil
	})

	if config == nil {
		return nil, errors.New("backup config is empty")
	}

	if config.GetInstanceName() == "" {
		return nil, errors.New("instance name is empty")
	}

	if config.GetS3() == nil {
		return nil, errors.New("s3 config is empty")
	}

	return config, nil
}

func (b *Backup) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ticker != nil {
		b.ticker.Stop()
		b.ticker = nil
	}

	return nil
}
