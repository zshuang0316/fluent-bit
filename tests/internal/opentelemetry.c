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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
// #include "../../plugins/in_opentelemetry/opentelemetry.h"
#include <fluent-bit/flb_opentelemetry.h>
#include <msgpack.h>
#include <string.h>

#include "flb_tests_internal.h"

// Remove the error_map struct and otel_error_map array from here
// as they will be moved to flb_opentelemetry.h

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
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_destroy(&dec);
        return NULL;
    }

    json = flb_msgpack_to_json_str(1024, event.metadata);
    printf("json -> %s\n", json);exit(0);
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

    ret = flb_otel_utils_hex_to_id((char *)hex, strlen(hex), out, sizeof(out));
    TEST_CHECK(ret == 0);
    TEST_CHECK(memcmp(out, expect, sizeof(expect)) == 0);
}

void test_convert_string_number_to_u64()
{
    uint64_t val;

    val = flb_otel_utils_convert_string_number_to_u64("123456", 6);
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

    index = flb_otel_utils_find_map_entry_by_key(map, "bar", 0, FLB_TRUE);
    TEST_CHECK(index == 1);

    index = flb_otel_utils_find_map_entry_by_key(map, "bar", 0, FLB_FALSE);
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

    ret = flb_otel_utils_json_payload_get_wrapped_value(&up.data, &val, &type);
    TEST_CHECK(ret == 0);
    TEST_CHECK(type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->via.str.size == 3);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);
}

#define OTEL_TEST_CASES_PATH      FLB_TESTS_DATA_PATH "/data/opentelemetry/test_cases.json"

void test_opentelemetry_cases()
{
    int ret;
    char *cases_json;
    char *tmp_buf;
    size_t tmp_size;
    int type;
    msgpack_unpacked result;
    msgpack_object *root;
    size_t i;

    cases_json = mk_file_to_buffer(OTEL_TEST_CASES_PATH);
    TEST_CHECK(cases_json != NULL);
    if (cases_json == NULL) {
        flb_error("could not read test cases from '%s'", OTEL_TEST_CASES_PATH);
        return;
    }

    ret = flb_pack_json(cases_json, strlen(cases_json), &tmp_buf, &tmp_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_error("could not convert test cases to msgpack from file '%s'", OTEL_TEST_CASES_PATH);
        flb_free(cases_json);
        return;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, tmp_buf, tmp_size, NULL);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    root = &result.data;
    printf("\n");

    for (i = 0; i < root->via.map.size; i++) {
        msgpack_object *case_obj;
        char *input_json;
        int error_status = 0;
        int empty_payload = FLB_FALSE;
        struct flb_log_event_encoder enc;
        msgpack_object *expected;
        msgpack_object *exp_err;
        char *meta_json;
        char *body_json;
        char *log_json;
        char *expect_meta;
        char *expect_body;
        char *expect_log;
        char *case_name;

        /* put the test name in a new buffer to avoid referencing msgpack object directly */
        case_name = flb_malloc(root->via.map.ptr[i].key.via.str.size + 1);
        if (!case_name) {
            flb_error("could not allocate memory for case name");
            flb_free(cases_json);
            msgpack_unpacked_destroy(&result);
            return;
        }
        memcpy(case_name, root->via.map.ptr[i].key.via.str.ptr, root->via.map.ptr[i].key.via.str.size);
        case_name[root->via.map.ptr[i].key.via.str.size] = '\0';
        printf(">> running test case '%s'\n", case_name);

        case_obj = &root->via.map.ptr[i].val;

        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "input", 0, FLB_TRUE);
        TEST_CHECK(ret >= 0);
        input_json = flb_msgpack_to_json_str(1024, &case_obj->via.map.ptr[ret].val);
        TEST_CHECK(input_json != NULL);

        ret = flb_log_event_encoder_init(&enc, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
        TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);

        /* Successful case */
        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "expected", 0, FLB_TRUE);
        if (ret >= 0) {
            expected = &case_obj->via.map.ptr[ret].val;

            /* check if we do expect an ok but an empty response (no ingestion) */
            ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "empty_payload", 0, FLB_TRUE);
            if (ret >= 0) {
                if (expected->via.map.ptr[ret].val.type != MSGPACK_OBJECT_BOOLEAN) {
                    flb_error("expected 'empty_payload' to be a boolean");
                    flb_free(input_json);
                    flb_log_event_encoder_destroy(&enc);
                    flb_free(case_name);
                    msgpack_unpacked_destroy(&result);
                    flb_free(cases_json);
                    return;
                }
                empty_payload = expected->via.map.ptr[ret].val.via.boolean;
            }
            else {
                /* if 'empty_payload' is not specified, we assume it's false */
                empty_payload = FLB_FALSE;
            }

            if (empty_payload == FLB_FALSE) {
                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "metadata", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_meta = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val);
                TEST_CHECK(expect_meta != NULL);

                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "body", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_body = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val);
                TEST_CHECK(expect_body != NULL);

                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "log", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_log = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val);
                TEST_CHECK(expect_log != NULL);
            }

            /* try to encode the OTLP JSON as messagepack */
            ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), &error_status);
            TEST_CHECK_(ret == 0, "case %s", case_name);

            if (empty_payload == FLB_FALSE) {
                meta_json = get_group_metadata(enc.output_buffer, enc.output_length);
                TEST_CHECK(strcmp(meta_json, expect_meta) == 0);

                body_json = get_group_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(strcmp(body_json, expect_body) == 0);

                log_json = get_log_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(strcmp(log_json, expect_log) == 0);
            }
            else {
                /* if we expect an empty payload, there should be no metadata, body or log */
                meta_json = get_group_metadata(enc.output_buffer, enc.output_length);
                TEST_CHECK(meta_json == NULL);

                body_json = get_group_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(body_json == NULL);

                log_json = get_log_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(log_json == NULL);

                /* check that the output buffer is empty */
                TEST_CHECK(enc.output_length == 0);

                /* check the output status */
                TEST_CHECK(error_status == FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD);
            }

            flb_free(meta_json);
            flb_free(body_json);
            flb_free(log_json);
            flb_free(expect_meta);
            flb_free(expect_body);
            flb_free(expect_log);
        }
        else {
            int exp_code;
            int exp_msg_size;
            const char *exp_msg;
            char *error_str;
            char *message_str;
            char tmp[128];
            msgpack_object *code_obj;
            msgpack_object *msg_obj;

            ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "expected_error", 0, FLB_TRUE);
            TEST_CHECK(ret >= 0);

            exp_err = &case_obj->via.map.ptr[ret].val;
            ret = flb_otel_utils_find_map_entry_by_key(&exp_err->via.map, "code", 0, FLB_TRUE);
            TEST_CHECK(ret >= 0);
            code_obj = &exp_err->via.map.ptr[ret].val;

            TEST_CHECK(code_obj->type == MSGPACK_OBJECT_STR);
            TEST_CHECK(code_obj->via.str.size < sizeof(tmp));
            memcpy(tmp, code_obj->via.str.ptr, code_obj->via.str.size);
            tmp[code_obj->via.str.size] = '\0';
            exp_code = flb_otel_error_code(tmp);

            /* try to encode it */
            ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), &error_status);
            printf("return status: %i, error_status: %i\n", ret, error_status);
            TEST_CHECK_(ret < 0, "test case '%s' should fail", case_name);
            TEST_CHECK_(error_status == exp_code,
                        "expected error code=%i, returned error_status=%i (%s)",
                        exp_code, error_status,
                        flb_otel_error_msg(error_status));
            if (error_status != exp_code) {
                break;
            }

            /*
             * check that 'error_status' matches the expected error code from the JSON
             * file, convert the numeric error code into it string representation name
             */
            error_str = (char *) flb_otel_error_msg(error_status);
            TEST_CHECK(error_str != NULL);

            memcpy(tmp, code_obj->via.str.ptr, code_obj->via.str.size);
            tmp[code_obj->via.str.size] = '\0';

            TEST_CHECK(strcmp(tmp, error_str) == 0);
        }

        flb_log_event_encoder_destroy(&enc);
        flb_free(input_json);
    }

    msgpack_unpacked_destroy(&result);
    flb_free(tmp_buf);
    flb_free(cases_json);
}

/* Test list */
TEST_LIST = {
    { "hex_to_id", test_hex_to_id },
    { "convert_string_number_to_u64", test_convert_string_number_to_u64 },
    { "find_map_entry_by_key", test_find_map_entry_by_key },
    { "json_payload_get_wrapped_value", test_json_payload_get_wrapped_value },
    { "opentelemetry_cases", test_opentelemetry_cases },
    { 0 }
};

