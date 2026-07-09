package legacyruntime

import (
	"errors"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/chore"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

func SaveBackupOption(db chore.DB, opt contractbackup.Option) (contractbackup.Option, error) {
	legacyOpt := backupOptionToLegacy(opt)
	err := db.Batch(func(s *config.Setting) error {
		s.SetBackup(legacyOpt)
		return nil
	})
	if err != nil {
		return contractbackup.Option{}, err
	}
	return backupOptionFromLegacy(legacyOpt), nil
}

func EnsureBackupOption(db chore.DB) (contractbackup.Option, error) {
	var cc *config.BackupOption
	_ = db.Batch(func(s *config.Setting) error {
		cc = s.GetBackup()
		if cc == nil {
			cc = &config.BackupOption{}
			s.SetBackup(cc)
		}
		ensureLegacyS3(cc)
		if cc.GetInstanceName() == "" {
			cc.SetInstanceName(id.GenerateUUID().String())
		}
		return nil
	})
	return backupOptionFromLegacy(cc), nil
}

func BackupRuntimeOption(db chore.DB) (contractbackup.Option, error) {
	var cc *config.BackupOption
	_ = db.Batch(func(s *config.Setting) error {
		cc = s.GetBackup()
		return nil
	})

	if cc == nil {
		return contractbackup.Option{}, nil
	}
	if cc.GetInstanceName() == "" {
		return contractbackup.Option{}, errors.New("instance name is empty")
	}
	if cc.GetS3() == nil {
		return contractbackup.Option{}, errors.New("s3 config is empty")
	}
	return backupOptionFromLegacy(cc), nil
}

func SaveBackupHash(db chore.DB, hash string) error {
	return db.Batch(func(s *config.Setting) error {
		if s.GetBackup() == nil {
			s.SetBackup(&config.BackupOption{})
		}
		s.GetBackup().SetLastBackupHash(hash)
		return nil
	})
}

func backupOptionFromLegacy(in *config.BackupOption) contractbackup.Option {
	if in == nil {
		return contractbackup.Option{}
	}
	out := contractbackup.Option{
		InstanceName:   in.GetInstanceName(),
		Interval:       in.GetInterval(),
		LastBackupHash: in.GetLastBackupHash(),
	}
	if s3 := in.GetS3(); s3 != nil {
		out.S3 = contractbackup.S3{
			Enabled:      s3.GetEnabled(),
			AccessKey:    s3.GetAccessKey(),
			SecretKey:    s3.GetSecretKey(),
			Bucket:       s3.GetBucket(),
			Region:       s3.GetRegion(),
			EndpointURL:  s3.GetEndpointUrl(),
			UsePathStyle: s3.GetUsePathStyle(),
			StorageClass: s3.GetStorageClass(),
		}
	}
	return out
}

func backupOptionToLegacy(in contractbackup.Option) *config.BackupOption {
	return &config.BackupOption{
		InstanceName:   in.InstanceName,
		Interval:       in.Interval,
		LastBackupHash: in.LastBackupHash,
		S3: &config.S3{
			Enabled:      in.S3.Enabled,
			AccessKey:    in.S3.AccessKey,
			SecretKey:    in.S3.SecretKey,
			Bucket:       in.S3.Bucket,
			Region:       in.S3.Region,
			EndpointUrl:  in.S3.EndpointURL,
			UsePathStyle: in.S3.UsePathStyle,
			StorageClass: in.S3.StorageClass,
		},
	}
}

func ensureLegacyS3(cc *config.BackupOption) {
	if cc.GetS3() != nil {
		return
	}
	cc.SetS3(config.S3_builder{
		Enabled:      new(false),
		AccessKey:    new(""),
		SecretKey:    new(""),
		Bucket:       new(""),
		EndpointUrl:  new(""),
		Region:       new(""),
		UsePathStyle: new(false),
	}.Build())
}
