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

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "yb/rocksdb/db/builder.h"
#include "yb/rocksdb/db/db_impl.h"
#include "yb/rocksdb/db/dbformat.h"
#include "yb/rocksdb/db/table_properties_collector.h"
#include "yb/rocksdb/flush_block_policy.h"
#include "yb/rocksdb/immutable_options.h"
#include "yb/rocksdb/table.h"
#include "yb/rocksdb/table/block_based_table_factory.h"
#include "yb/rocksdb/table/meta_blocks.h"
#include "yb/rocksdb/table/plain_table_factory.h"
#include "yb/rocksdb/table/table_builder.h"
#include "yb/rocksdb/util/coding.h"
#include "yb/rocksdb/util/file_reader_writer.h"
#include "yb/rocksdb/util/testutil.h"

#include "yb/util/test_macros.h"

namespace rocksdb {

class TablePropertiesTest : public RocksDBTest,
                            public testing::WithParamInterface<bool> {
 public:
  void SetUp() override { backward_mode_ = GetParam(); }

  bool backward_mode_;
};

// Utilities test functions
namespace {
static const uint32_t kTestColumnFamilyId = 66;

void MakeBuilder(const Options& options, const ImmutableCFOptions& ioptions,
                 const InternalKeyComparatorPtr& internal_comparator,
                 const IntTblPropCollectorFactories& int_tbl_prop_collector_factories,
                 std::unique_ptr<WritableFileWriter>* writable,
                 std::unique_ptr<TableBuilder>* builder) {
  unique_ptr<WritableFile> wf(new test::StringSink);
  writable->reset(new WritableFileWriter(std::move(wf), EnvOptions()));

  *builder = NewTableBuilder(
      ioptions, internal_comparator, int_tbl_prop_collector_factories,
      kTestColumnFamilyId /* column_family_id */, writable->get(),
      options.compression, options.compression_opts);
}
}  // namespace

// Collects keys that starts with "A" in a table.
class RegularKeysStartWithA: public TablePropertiesCollector {
 public:
  const char* Name() const override { return "RegularKeysStartWithA"; }

  Status Finish(UserCollectedProperties* properties) override {
     std::string encoded;
     std::string encoded_num_puts;
     std::string encoded_num_deletes;
     std::string encoded_num_single_deletes;
     std::string encoded_num_size_changes;
     PutVarint32(&encoded, count_);
     PutVarint32(&encoded_num_puts, num_puts_);
     PutVarint32(&encoded_num_deletes, num_deletes_);
     PutVarint32(&encoded_num_single_deletes, num_single_deletes_);
     PutVarint32(&encoded_num_size_changes, num_size_changes_);
     *properties = UserCollectedProperties{
         {"TablePropertiesTest", message_},
         {"Count", encoded},
         {"NumPuts", encoded_num_puts},
         {"NumDeletes", encoded_num_deletes},
         {"NumSingleDeletes", encoded_num_single_deletes},
         {"NumSizeChanges", encoded_num_size_changes},
     };
     return Status::OK();
  }

  Status AddUserKey(const Slice& user_key, const Slice& value, EntryType type,
                    SequenceNumber seq, uint64_t file_size) override {
    // simply asssume all user keys are not empty.
    if (user_key.data()[0] == 'A') {
      ++count_;
    }
    if (type == kEntryPut) {
      num_puts_++;
    } else if (type == kEntryDelete) {
      num_deletes_++;
    } else if (type == kEntrySingleDelete) {
      num_single_deletes_++;
    }
    if (file_size < file_size_) {
      message_ = "File size should not decrease.";
    } else if (file_size != file_size_) {
      num_size_changes_++;
    }

    return Status::OK();
  }

  UserCollectedProperties GetReadableProperties() const override {
    return UserCollectedProperties{};
  }

 private:
  std::string message_ = "Rocksdb";
  uint32_t count_ = 0;
  uint32_t num_puts_ = 0;
  uint32_t num_deletes_ = 0;
  uint32_t num_single_deletes_ = 0;
  uint32_t num_size_changes_ = 0;
  uint64_t file_size_ = 0;
};

// Collects keys that starts with "A" in a table. Backward compatible mode
// It is also used to test internal key table property collector
class RegularKeysStartWithABackwardCompatible
    : public TablePropertiesCollector {
 public:
  const char* Name() const override { return "RegularKeysStartWithA"; }

  Status Finish(UserCollectedProperties* properties) override {
    std::string encoded;
    PutVarint32(&encoded, count_);
    *properties = UserCollectedProperties{{"TablePropertiesTest", "Rocksdb"},
                                          {"Count", encoded}};
    return Status::OK();
  }

  Status Add(const Slice& user_key, const Slice& value) override {
    // simply asssume all user keys are not empty.
    if (user_key.data()[0] == 'A') {
      ++count_;
    }
    return Status::OK();
  }

  UserCollectedProperties GetReadableProperties() const override {
    return UserCollectedProperties{};
  }

 private:
  uint32_t count_ = 0;
};

class RegularKeysStartWithAInternal : public IntTblPropCollector {
 public:
  const char* Name() const override { return "RegularKeysStartWithA"; }

  Status Finish(UserCollectedProperties* properties) override {
    std::string encoded;
    PutVarint32(&encoded, count_);
    *properties = UserCollectedProperties{{"TablePropertiesTest", "Rocksdb"},
                                          {"Count", encoded}};
    return Status::OK();
  }

  Status InternalAdd(const Slice& user_key, const Slice& value,
                     uint64_t file_size) override {
    // simply asssume all user keys are not empty.
    if (user_key.data()[0] == 'A') {
      ++count_;
    }
    return Status::OK();
  }

  UserCollectedProperties GetReadableProperties() const override {
    return UserCollectedProperties{};
  }

 private:
  uint32_t count_ = 0;
};

class RegularKeysStartWithAFactory : public IntTblPropCollectorFactory,
                                     public TablePropertiesCollectorFactory {
 public:
  explicit RegularKeysStartWithAFactory(bool backward_mode)
      : backward_mode_(backward_mode) {}
  virtual TablePropertiesCollector* CreateTablePropertiesCollector(
      TablePropertiesCollectorFactory::Context context) override {
    EXPECT_EQ(kTestColumnFamilyId, context.column_family_id);
    if (!backward_mode_) {
      return new RegularKeysStartWithA();
    } else {
      return new RegularKeysStartWithABackwardCompatible();
    }
  }
  virtual IntTblPropCollector* CreateIntTblPropCollector(
      uint32_t column_family_id) override {
    return new RegularKeysStartWithAInternal();
  }
  const char* Name() const override { return "RegularKeysStartWithA"; }

  bool backward_mode_;
};

class FlushBlockEveryThreePolicy : public FlushBlockPolicy {
 public:
  bool Update(const Slice& key, const Slice& value) override {
    return (++count_ % 3U == 0);
  }

 private:
  uint64_t count_ = 0;
};

class FlushBlockEveryThreePolicyFactory : public FlushBlockPolicyFactory {
 public:
  FlushBlockEveryThreePolicyFactory() {}

  const char* Name() const override {
    return "FlushBlockEveryThreePolicyFactory";
  }

  FlushBlockPolicy* NewFlushBlockPolicy(
      const BlockBasedTableOptions& table_options,
      const BlockBuilder& data_block_builder) const override {
    return new FlushBlockEveryThreePolicy;
  }
};

extern const uint64_t kBlockBasedTableMagicNumber;
extern const uint64_t kPlainTableMagicNumber;
namespace {
void TestCustomizedTablePropertiesCollector(
    bool backward_mode, uint64_t magic_number, bool test_int_tbl_prop_collector,
    const Options& options, const InternalKeyComparatorPtr& internal_comparator) {
  // make sure the entries will be inserted with order.
  std::map<std::pair<std::string, ValueType>, std::string> kvs = {
      {{"About   ", kTypeValue}, "val5"},  // starts with 'A'
      {{"Abstract", kTypeValue}, "val2"},  // starts with 'A'
      {{"Around  ", kTypeValue}, "val7"},  // starts with 'A'
      {{"Beyond  ", kTypeValue}, "val3"},
      {{"Builder ", kTypeValue}, "val1"},
      {{"Love    ", kTypeDeletion}, ""},
      {{"Cancel  ", kTypeValue}, "val4"},
      {{"Find    ", kTypeValue}, "val6"},
      {{"Rocks   ", kTypeDeletion}, ""},
      {{"Foo     ", kTypeSingleDeletion}, ""},
  };

  // -- Step 1: build table
  std::unique_ptr<TableBuilder> builder;
  std::unique_ptr<WritableFileWriter> writer;
  const ImmutableCFOptions ioptions(options);
  IntTblPropCollectorFactories int_tbl_prop_collector_factories;
  if (test_int_tbl_prop_collector) {
    int_tbl_prop_collector_factories.emplace_back(
        new RegularKeysStartWithAFactory(backward_mode));
  } else {
    GetIntTblPropCollectorFactory(options, &int_tbl_prop_collector_factories);
  }
  MakeBuilder(options,
              ioptions,
              internal_comparator,
              int_tbl_prop_collector_factories,
              &writer,
              &builder);

  SequenceNumber seqNum = 0U;
  for (const auto& kv : kvs) {
    InternalKey ikey(kv.first.first, seqNum++, kv.first.second);
    builder->Add(ikey.Encode(), kv.second);
  }
  ASSERT_OK(builder->Finish());
  ASSERT_OK(writer->Flush());

  // -- Step 2: Read properties
  test::StringSink* fwf =
      static_cast<test::StringSink*>(writer->writable_file());
  std::unique_ptr<RandomAccessFileReader> fake_file_reader(
      test::GetRandomAccessFileReader(
          new test::StringSource(fwf->contents())));
  TableProperties* props;
  Status s = ReadTableProperties(fake_file_reader.get(), fwf->contents().size(),
                                 magic_number, Env::Default(), nullptr, &props);
  std::unique_ptr<TableProperties> props_guard(props);
  ASSERT_OK(s);

  auto user_collected = props->user_collected_properties;

  ASSERT_NE(user_collected.find("TablePropertiesTest"), user_collected.end());
  ASSERT_EQ("Rocksdb", user_collected.at("TablePropertiesTest"));

  uint32_t starts_with_A = 0;
  ASSERT_NE(user_collected.find("Count"), user_collected.end());
  Slice key(user_collected.at("Count"));
  ASSERT_TRUE(GetVarint32(&key, &starts_with_A));
  ASSERT_EQ(3u, starts_with_A);

  if (!backward_mode && !test_int_tbl_prop_collector) {
    uint32_t num_puts;
    ASSERT_NE(user_collected.find("NumPuts"), user_collected.end());
    Slice key_puts(user_collected.at("NumPuts"));
    ASSERT_TRUE(GetVarint32(&key_puts, &num_puts));
    ASSERT_EQ(7u, num_puts);

    uint32_t num_deletes;
    ASSERT_NE(user_collected.find("NumDeletes"), user_collected.end());
    Slice key_deletes(user_collected.at("NumDeletes"));
    ASSERT_TRUE(GetVarint32(&key_deletes, &num_deletes));
    ASSERT_EQ(2u, num_deletes);

    uint32_t num_single_deletes;
    ASSERT_NE(user_collected.find("NumSingleDeletes"), user_collected.end());
    Slice key_single_deletes(user_collected.at("NumSingleDeletes"));
    ASSERT_TRUE(GetVarint32(&key_single_deletes, &num_single_deletes));
    ASSERT_EQ(1u, num_single_deletes);

    uint32_t num_size_changes;
    ASSERT_NE(user_collected.find("NumSizeChanges"), user_collected.end());
    Slice key_size_changes(user_collected.at("NumSizeChanges"));
    ASSERT_TRUE(GetVarint32(&key_size_changes, &num_size_changes));
    ASSERT_GE(num_size_changes, 2u);
  }
}
}  // namespace

TEST_P(TablePropertiesTest, CustomizedTablePropertiesCollector) {
  // Test properties collectors with internal keys or regular keys
  // for block based table
  for (bool encode_as_internal : { true, false }) {
    Options options;
    BlockBasedTableOptions table_options;
    table_options.flush_block_policy_factory =
        std::make_shared<FlushBlockEveryThreePolicyFactory>();
    options.table_factory.reset(NewBlockBasedTableFactory(table_options));

    auto ikc = std::make_shared<test::PlainInternalKeyComparator>(options.comparator);
    std::shared_ptr<TablePropertiesCollectorFactory> collector_factory(
        new RegularKeysStartWithAFactory(backward_mode_));
    options.table_properties_collector_factories.resize(1);
    options.table_properties_collector_factories[0] = collector_factory;

    TestCustomizedTablePropertiesCollector(backward_mode_,
                                           kBlockBasedTableMagicNumber,
                                           encode_as_internal, options, ikc);

#ifndef ROCKSDB_LITE  // PlainTable is not supported in Lite
    // test plain table
    PlainTableOptions plain_table_options;
    plain_table_options.user_key_len = 8;
    plain_table_options.bloom_bits_per_key = 8;
    plain_table_options.hash_table_ratio = 0;

    options.table_factory =
        std::make_shared<PlainTableFactory>(plain_table_options);
    TestCustomizedTablePropertiesCollector(backward_mode_,
                                           kPlainTableMagicNumber,
                                           encode_as_internal, options, ikc);
#endif  // !ROCKSDB_LITE
  }
}

namespace {
void TestInternalKeyPropertiesCollector(
    bool backward_mode, uint64_t magic_number, bool sanitized,
    std::shared_ptr<TableFactory> table_factory) {
  InternalKey keys[] = {
      InternalKey("A       ", 0, ValueType::kTypeValue),
      InternalKey("B       ", 1, ValueType::kTypeValue),
      InternalKey("C       ", 2, ValueType::kTypeValue),
      InternalKey("W       ", 3, ValueType::kTypeDeletion),
      InternalKey("X       ", 4, ValueType::kTypeDeletion),
      InternalKey("Y       ", 5, ValueType::kTypeDeletion),
      InternalKey("Z       ", 6, ValueType::kTypeDeletion),
      InternalKey("a       ", 7, ValueType::kTypeSingleDeletion),
  };

  std::unique_ptr<TableBuilder> builder;
  std::unique_ptr<WritableFileWriter> writable;
  Options options;
  auto pikc = std::make_shared<test::PlainInternalKeyComparator>(options.comparator);

  IntTblPropCollectorFactories int_tbl_prop_collector_factories;
  options.table_factory = table_factory;
  if (sanitized) {
    options.table_properties_collector_factories.emplace_back(
        new RegularKeysStartWithAFactory(backward_mode));
    // with sanitization, even regular properties collector will be able to
    // handle internal keys.
    auto comparator = options.comparator;
    // HACK: Set options.info_log to avoid writing log in
    // SanitizeOptions().
    options.info_log = std::make_shared<test::NullLogger>();
    options = SanitizeOptions("db",            // just a place holder
                              pikc.get(),
                              options);
    GetIntTblPropCollectorFactory(options, &int_tbl_prop_collector_factories);
    options.comparator = comparator;
  } else {
    int_tbl_prop_collector_factories.emplace_back(
        new InternalKeyPropertiesCollectorFactory);
  }
  const ImmutableCFOptions ioptions(options);

  for (int iter = 0; iter < 2; ++iter) {
    MakeBuilder(options,
                ioptions,
                pikc,
                int_tbl_prop_collector_factories,
                &writable,
                &builder);
    for (const auto& k : keys) {
      builder->Add(k.Encode(), "val");
    }

    ASSERT_OK(builder->Finish());
    ASSERT_OK(writable->Flush());

    test::StringSink* fwf =
        static_cast<test::StringSink*>(writable->writable_file());
    unique_ptr<RandomAccessFileReader> reader(test::GetRandomAccessFileReader(
        new test::StringSource(fwf->contents())));
    TableProperties* props;
    Status s =
        ReadTableProperties(reader.get(), fwf->contents().size(), magic_number,
                            Env::Default(), nullptr, &props);
    ASSERT_OK(s);

    std::unique_ptr<TableProperties> props_guard(props);
    auto user_collected = props->user_collected_properties;
    uint64_t deleted = GetDeletedKeys(user_collected);
    ASSERT_EQ(5u, deleted);  // deletes + single-deletes

    if (sanitized) {
      uint32_t starts_with_A = 0;
      ASSERT_NE(user_collected.find("Count"), user_collected.end());
      Slice key(user_collected.at("Count"));
      ASSERT_TRUE(GetVarint32(&key, &starts_with_A));
      ASSERT_EQ(1u, starts_with_A);

      if (!backward_mode) {
        uint32_t num_puts;
        ASSERT_NE(user_collected.find("NumPuts"), user_collected.end());
        Slice key_puts(user_collected.at("NumPuts"));
        ASSERT_TRUE(GetVarint32(&key_puts, &num_puts));
        ASSERT_EQ(3u, num_puts);

        uint32_t num_deletes;
        ASSERT_NE(user_collected.find("NumDeletes"), user_collected.end());
        Slice key_deletes(user_collected.at("NumDeletes"));
        ASSERT_TRUE(GetVarint32(&key_deletes, &num_deletes));
        ASSERT_EQ(4u, num_deletes);

        uint32_t num_single_deletes;
        ASSERT_NE(user_collected.find("NumSingleDeletes"),
                  user_collected.end());
        Slice key_single_deletes(user_collected.at("NumSingleDeletes"));
        ASSERT_TRUE(GetVarint32(&key_single_deletes, &num_single_deletes));
        ASSERT_EQ(1u, num_single_deletes);
      }
    }
  }
}
}  // namespace

TEST_P(TablePropertiesTest, InternalKeyPropertiesCollector) {
  TestInternalKeyPropertiesCollector(
      backward_mode_, kBlockBasedTableMagicNumber, true /* sanitize */,
      std::make_shared<BlockBasedTableFactory>());
  if (backward_mode_) {
    TestInternalKeyPropertiesCollector(
        backward_mode_, kBlockBasedTableMagicNumber, false /* not sanitize */,
        std::make_shared<BlockBasedTableFactory>());
  }

#ifndef ROCKSDB_LITE  // PlainTable is not supported in Lite
  PlainTableOptions plain_table_options;
  plain_table_options.user_key_len = 8;
  plain_table_options.bloom_bits_per_key = 8;
  plain_table_options.hash_table_ratio = 0;

  TestInternalKeyPropertiesCollector(
      backward_mode_, kPlainTableMagicNumber, false /* not sanitize */,
      std::make_shared<PlainTableFactory>(plain_table_options));
#endif  // !ROCKSDB_LITE
}

INSTANTIATE_TEST_CASE_P(InternalKeyPropertiesCollector, TablePropertiesTest,
                        ::testing::Bool());

INSTANTIATE_TEST_CASE_P(CustomizedTablePropertiesCollector, TablePropertiesTest,
                        ::testing::Bool());

}  // namespace rocksdb

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
