package badger

import (
	"github.com/dgraph-io/badger/v4/y"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func BadgerCollector(namespace string) prometheus.Collector {
	BADGER_METRIC_PREFIX := y.BADGER_METRIC_PREFIX
	exports := map[string]*prometheus.Desc{}
	metricnames := []string{
		BADGER_METRIC_PREFIX + "read_num_vlog",
		BADGER_METRIC_PREFIX + "read_bytes_vlog",
		BADGER_METRIC_PREFIX + "write_num_vlog",
		BADGER_METRIC_PREFIX + "write_bytes_vlog",
		BADGER_METRIC_PREFIX + "read_bytes_lsm",
		BADGER_METRIC_PREFIX + "write_bytes_l0",
		BADGER_METRIC_PREFIX + "write_bytes_compaction",
		BADGER_METRIC_PREFIX + "get_num_lsm",
		BADGER_METRIC_PREFIX + "hit_num_lsm_bloom_filter",
		BADGER_METRIC_PREFIX + "get_num_memtable",
		BADGER_METRIC_PREFIX + "get_num_user",
		BADGER_METRIC_PREFIX + "put_num_user",
		BADGER_METRIC_PREFIX + "write_bytes_user",
		BADGER_METRIC_PREFIX + "get_with_result_num_user",
		BADGER_METRIC_PREFIX + "iterator_num_user",
		BADGER_METRIC_PREFIX + "size_bytes_lsm",
		BADGER_METRIC_PREFIX + "size_bytes_vlog",
		BADGER_METRIC_PREFIX + "write_pending_num_memtable",
		BADGER_METRIC_PREFIX + "compaction_current_num_lsm",
	}
	for _, name := range metricnames {
		exportname := name
		if exportname != "" {
			exportname = namespace + "_" + exportname
		}
		exports[name] = prometheus.NewDesc(
			exportname,
			"badger db metric "+name,
			nil, nil,
		)
	}
	return collectors.NewExpvarCollector(exports)
}
