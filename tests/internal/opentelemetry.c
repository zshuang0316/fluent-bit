/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_otel_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
// #include "../../plugins/in_opentelemetry/opentelemetry.h"
#include <fluent-bit/flb_opentelemetry.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

/* --------------------------------------------------------------- */
/* Helpers                                                        */
/* --------------------------------------------------------------- */

static char *get_group_metadata(void *chunk, size_t size)
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    char *json;

    ret = flb_log_event_decoder_init(&dec, chunk, size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    ret = flb_log_event_decoder_next(&dec, &event);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_destroy(&dec);
        return NULL;
    }

    json = flb_msgpack_to_json_str(1024, event.metadata);
    flb_log_event_decoder_destroy(&dec);
    return json;
}

static char *get_group_body(void *chunk, size_t size)
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    char *json;

    ret = flb_log_event_decoder_init(&dec, chunk, size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    ret = flb_log_event_decoder_next(&dec, &event);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_destroy(&dec);
        return NULL;
    }

    json = flb_msgpack_to_json_str(1024, event.body);
    flb_log_event_decoder_destroy(&dec);
    return json;
}

static char *get_log_body(void *chunk, size_t size)
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    char *json;

    ret = flb_log_event_decoder_init(&dec, chunk, size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    /* skip group header */
    flb_log_event_decoder_next(&dec, &event);

    /* log record */
    flb_log_event_decoder_next(&dec, &event);

    json = flb_msgpack_to_json_str(1024, event.body);
    flb_log_event_decoder_destroy(&dec);
    return json;
}

/* --------------------------------------------------------------- */
/* Unit tests                                                     */
/* --------------------------------------------------------------- */

void test_hex_to_id()
{
    unsigned char out[16];
    int ret;
    const char *hex = "000102030405060708090a0b0c0d0e0f";
    unsigned char expect[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    ret = hex_to_id((char *)hex, strlen(hex), out, sizeof(out));
    TEST_CHECK(ret == 0);
    TEST_CHECK(memcmp(out, expect, sizeof(expect)) == 0);
}

void test_convert_string_number_to_u64()
{
    uint64_t val;

    val = convert_string_number_to_u64("123456", 6);
    TEST_CHECK(val == 123456ULL);
}

void test_find_map_entry_by_key()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked up;
    int index;
    msgpack_object_map *map;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 2);
    msgpack_pack_str(&pck, 3); msgpack_pack_str_body(&pck, "foo", 3);
    msgpack_pack_int(&pck, 1);
    msgpack_pack_str(&pck, 3); msgpack_pack_str_body(&pck, "Bar", 3);
    msgpack_pack_int(&pck, 2);

    msgpack_unpacked_init(&up);
    msgpack_unpack_next(&up, sbuf.data, sbuf.size, NULL);
    map = &up.data.via.map;

    index = find_map_entry_by_key(map, "bar", 0, FLB_TRUE);
    TEST_CHECK(index == 1);

    index = find_map_entry_by_key(map, "bar", 0, FLB_FALSE);
    TEST_CHECK(index == -1);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);
}

void test_json_payload_get_wrapped_value()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked up;
    msgpack_object *val;
    int type;
    int ret;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 11);
    msgpack_pack_str_body(&pck, "stringValue", 11);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "abc", 3);

    msgpack_unpacked_init(&up);
    msgpack_unpack_next(&up, sbuf.data, sbuf.size, NULL);

    ret = json_payload_get_wrapped_value(&up.data, &val, &type);
    TEST_CHECK(ret == 0);
    TEST_CHECK(type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->via.str.size == 3);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);
}

#define OTEL_JSON_PATH            FLB_TESTS_DATA_PATH "/data/opentelemetry/input.json"
#define EXPECTED_METADATA_PATH    FLB_TESTS_DATA_PATH "/data/opentelemetry/expected_metadata.json"
#define EXPECTED_BODY_PATH        FLB_TESTS_DATA_PATH "/data/opentelemetry/expected_body.json"
#define EXPECTED_LOG_PATH         FLB_TESTS_DATA_PATH "/data/opentelemetry/expected_log.json"

void test_fluentbit_otel_json()
{
    int ret;
    int error_status = 0;
    char *input_json;
    char *expect_meta;
    char *expect_body;
    char *expect_log;
    char *meta_json;
    char *body_json;
    char *log_json;
    struct flb_input_instance ins;
    struct flb_input_plugin plugin;
    struct flb_log_event_encoder enc;

    memset(&plugin, 0, sizeof(plugin));
    plugin.name = "dummy";
    memset(&ins, 0, sizeof(ins));
    ins.log_level = FLB_LOG_OFF;
    ins.p = &plugin;

    ret = flb_log_event_encoder_init(&enc, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);

    input_json = mk_file_to_buffer(OTEL_JSON_PATH);
    TEST_CHECK(input_json != NULL);

    expect_meta = mk_file_to_buffer(EXPECTED_METADATA_PATH);
    TEST_CHECK(expect_meta != NULL);

    expect_body = mk_file_to_buffer(EXPECTED_BODY_PATH);
    TEST_CHECK(expect_body != NULL);

    expect_log = mk_file_to_buffer(EXPECTED_LOG_PATH);
    TEST_CHECK(expect_log != NULL);

    ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), &error_status);
    TEST_CHECK(ret == 0);

    meta_json = get_group_metadata(enc.output_buffer, enc.output_length);
    TEST_CHECK(meta_json != NULL);
    TEST_CHECK(strcmp(meta_json, expect_meta) == 0);

    body_json = get_group_body(enc.output_buffer, enc.output_length);
    TEST_CHECK(body_json != NULL);
    TEST_CHECK(strcmp(body_json, expect_body) == 0);

    log_json = get_log_body(enc.output_buffer, enc.output_length);
    TEST_CHECK(log_json != NULL);
    TEST_CHECK(strcmp(log_json, expect_log) == 0);

    flb_free(meta_json);
    flb_free(body_json);
    flb_free(log_json);
    flb_free(input_json);
    flb_free(expect_meta);
    flb_free(expect_body);
    flb_free(expect_log);
    flb_log_event_encoder_destroy(&enc);
}

/* Test list */
TEST_LIST = {
    { "hex_to_id", test_hex_to_id },
    { "convert_string_number_to_u64", test_convert_string_number_to_u64 },
    { "find_map_entry_by_key", test_find_map_entry_by_key },
    { "json_payload_get_wrapped_value", test_json_payload_get_wrapped_value },
    { "fluentbit_otel_json", test_fluentbit_otel_json },
    { 0 }
};

