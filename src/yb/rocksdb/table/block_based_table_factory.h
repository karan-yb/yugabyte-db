//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.
//
// The following only applies to changes made to this file as part of YugaByte development.
//
// Portions Copyright (c) YugaByte, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef YB_ROCKSDB_TABLE_BLOCK_BASED_TABLE_FACTORY_H
#define YB_ROCKSDB_TABLE_BLOCK_BASED_TABLE_FACTORY_H

#include <stdint.h>

#include <memory>
#include <string>

#include "yb/rocksdb/table.h"
#include "yb/rocksdb/table/block_based_table_reader.h"

namespace rocksdb {

struct EnvOptions;

using std::unique_ptr;
class BlockBasedTableBuilder;

class BlockBasedTableFactory : public TableFactory {
 public:
  explicit BlockBasedTableFactory(
      const BlockBasedTableOptions& table_options = BlockBasedTableOptions());

  ~BlockBasedTableFactory() {}

  const char* Name() const override { return "BlockBasedTable"; }

  Status NewTableReader(const TableReaderOptions& table_reader_options,
                        unique_ptr<RandomAccessFileReader>&& file,
                        uint64_t file_size,
                        unique_ptr<TableReader>* table_reader) const override;

  // This is a variant of virtual member function NewTableReader function with
  // added capability to control pre-fetching of blocks on BlockBasedTable::Open
  Status NewTableReader(const TableReaderOptions& table_reader_options,
                        unique_ptr<RandomAccessFileReader>&& file,
                        uint64_t file_size,
                        unique_ptr<TableReader>* table_reader,
                        DataIndexLoadMode prefetch_data_index,
                        PrefetchFilter prefetch_filter) const;

  bool IsSplitSstForWriteSupported() const override { return true; }

  // base_file should be not nullptr, data_file should either point to different file writer
  // or be nullptr in order to produce single SST file containing both data and metadata.
  std::unique_ptr<TableBuilder> NewTableBuilder(
      const TableBuilderOptions& table_builder_options,
      uint32_t column_family_id, WritableFileWriter* base_file,
      WritableFileWriter* data_file = nullptr) const override;

  // Sanitizes the specified DB Options.
  Status SanitizeOptions(const DBOptions& db_opts,
                         const ColumnFamilyOptions& cf_opts) const override;

  std::string GetPrintableTableOptions() const override;

  const BlockBasedTableOptions& table_options() const;

  void* GetOptions() override { return &table_options_; }

  std::shared_ptr<TableAwareReadFileFilter> NewTableAwareReadFileFilter(
      const ReadOptions &read_options, const Slice &user_key) const override;

 private:
  BlockBasedTableOptions table_options_;
};

extern const char kHashIndexPrefixesBlock[];
extern const char kHashIndexPrefixesMetadataBlock[];
extern const char kPropTrue[];
extern const char kPropFalse[];

inline const char* ToBlockBasedTablePropertyValue(bool value) {
  return value ? kPropTrue : kPropFalse;
}

}  // namespace rocksdb

#endif  // YB_ROCKSDB_TABLE_BLOCK_BASED_TABLE_FACTORY_H
