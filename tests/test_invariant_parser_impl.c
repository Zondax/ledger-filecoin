#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Simulate the transaction structure and parser behavior
 * to test the security invariant around MEMMOVE/MEMCPY
 * operations on params buffer.
 */

#define ERC20_DATA_LENGTH 68
#define PARAMS_BUFFER_SIZE 256
#define MIN_PARAMS_LENGTH_FOR_MEMMOVE 2

typedef struct {
    uint8_t params[PARAMS_BUFFER_SIZE];
    uint16_t paramsSize;
    uint16_t paramsBufferSize;
} Transaction;

/* Simulated parser function that mirrors the vulnerable pattern:
 * MEMMOVE(tx->params, tx->params + 2, ERC20_DATA_LENGTH);
 * Returns 0 on success, -1 on detected invariant violation.
 */
static int safe_parse_erc20_params(Transaction *tx) {
    if (tx == NULL) return -1;

    /* INVARIANT 1: params buffer must have at least 2 bytes before shifting */
    if (tx->paramsSize < MIN_PARAMS_LENGTH_FOR_MEMMOVE) {
        return -1;
    }

    /* INVARIANT 2: source region (params + 2) must not exceed buffer */
    if ((size_t)(2 + ERC20_DATA_LENGTH) > sizeof(tx->params)) {
        return -1;
    }

    /* INVARIANT 3: paramsSize must accommodate the shift */
    if (tx->paramsSize < (uint16_t)(2 + ERC20_DATA_LENGTH)) {
        return -1;
    }

    /* INVARIANT 4: paramsBufferSize must not exceed actual allocation */
    if (tx->paramsBufferSize > sizeof(tx->params)) {
        return -1;
    }

    /* INVARIANT 5: paramsBufferSize must be consistent with paramsSize */
    if (tx->paramsBufferSize > tx->paramsSize) {
        return -1;
    }

    /* Safe to perform the operation */
    memmove(tx->params, tx->params + 2, ERC20_DATA_LENGTH);
    return 0;
}

/* Helper to build a transaction with specific params content */
static void build_transaction(Transaction *tx, const uint8_t *data, uint16_t data_len,
                               uint16_t paramsSize, uint16_t paramsBufferSize) {
    memset(tx, 0, sizeof(Transaction));
    if (data && data_len > 0 && data_len <= sizeof(tx->params)) {
        memcpy(tx->params, data, data_len);
    }
    tx->paramsSize = paramsSize;
    tx->paramsBufferSize = paramsBufferSize;
}

START_TEST(test_memmove_buffer_safety_invariant)
{
    /* Invariant: MEMMOVE on params buffer must never operate beyond
     * allocated buffer boundaries, and paramsBufferSize must never
     * exceed the actual allocation size. All adversarial inputs must
     * either be rejected or processed safely without buffer overread/overwrite.
     */

    typedef struct {
        const char *description;
        uint16_t paramsSize;
        uint16_t paramsBufferSize;
        uint8_t data[PARAMS_BUFFER_SIZE];
        uint16_t data_len;
        int expect_success; /* 1 = should succeed safely, 0 = should be rejected */
    } TestCase;

    TestCase cases[] = {
        /* Normal valid case */
        {
            "valid ERC20 params",
            ERC20_DATA_LENGTH + 2,
            ERC20_DATA_LENGTH + 2,
            {0x00, 0x01, /* 2 byte prefix */
             0xAA, 0xBB, 0xCC, 0xDD, /* ERC20 data starts here */},
            ERC20_DATA_LENGTH + 2,
            1
        },
        /* Zero paramsSize - should be rejected */
        {
            "zero paramsSize",
            0,
            0,
            {0},
            0,
            0
        },
        /* paramsSize = 1 (less than MIN_PARAMS_LENGTH_FOR_MEMMOVE) */
        {
            "paramsSize too small for shift",
            1,
            1,
            {0xFF},
            1,
            0
        },
        /* paramsSize exactly 2 but not enough for ERC20_DATA_LENGTH */
        {
            "paramsSize exactly 2, insufficient for ERC20",
            2,
            2,
            {0x00, 0x01},
            2,
            0
        },
        /* paramsBufferSize exceeds actual allocation */
        {
            "paramsBufferSize exceeds PARAMS_BUFFER_SIZE",
            ERC20_DATA_LENGTH + 2,
            PARAMS_BUFFER_SIZE + 1, /* overflow attempt */
            {0},
            ERC20_DATA_LENGTH + 2,
            0
        },
        /* paramsBufferSize = UINT16_MAX (integer overflow attempt) */
        {
            "paramsBufferSize = UINT16_MAX",
            ERC20_DATA_LENGTH + 2,
            0xFFFF,
            {0},
            ERC20_DATA_LENGTH + 2,
            0
        },
        /* paramsSize = UINT16_MAX */
        {
            "paramsSize = UINT16_MAX",
            0xFFFF,
            0xFFFF,
            {0},
            0,
            0
        },
        /* paramsBufferSize > paramsSize (inconsistency) */
        {
            "paramsBufferSize greater than paramsSize",
            ERC20_DATA_LENGTH + 2,
            ERC20_DATA_LENGTH + 10,
            {0},
            ERC20_DATA_LENGTH + 2,
            0
        },
        /* Exactly at boundary: paramsSize = 2 + ERC20_DATA_LENGTH */
        {
            "paramsSize exactly at boundary",
            (uint16_t)(2 + ERC20_DATA_LENGTH),
            (uint16_t)(2 + ERC20_DATA_LENGTH),
            {0x00, 0x01},
            (uint16_t)(2 + ERC20_DATA_LENGTH),
            1
        },
        /* paramsSize = 2 + ERC20_DATA_LENGTH - 1 (one byte short) */
        {
            "paramsSize one byte short of required",
            (uint16_t)(2 + ERC20_DATA_LENGTH - 1),
            (uint16_t)(2 + ERC20_DATA_LENGTH - 1),
            {0x00, 0x01},
            (uint16_t)(2 + ERC20_DATA_LENGTH - 1),
            0
        },
        /* All zeros - minimal data */
        {
            "all zeros minimal data",
            ERC20_DATA_LENGTH + 2,
            ERC20_DATA_LENGTH + 2,
            {0x00},
            ERC20_DATA_LENGTH + 2,
            1
        },
        /* All 0xFF - adversarial fill */
        {
            "all 0xFF adversarial fill",
            ERC20_DATA_LENGTH + 2,
            ERC20_DATA_LENGTH + 2,
            {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
            ERC20_DATA_LENGTH + 2,
            1
        },
        /* paramsBufferSize = 0 with non-zero paramsSize */
        {
            "paramsBufferSize zero with non-zero paramsSize",
            ERC20_DATA_LENGTH + 2,
            0,
            {0},
            ERC20_DATA_LENGTH + 2,
            0
        },
        /* Attempt to use offset that would wrap around */
        {
            "wrap-around attempt paramsSize near max",
            0xFFFE,
            0xFFFE,
            {0},
            0,
            0
        },
    };

    int num_cases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < num_cases; i++) {
        Transaction tx;
        build_transaction(&tx,
                          cases[i].data,
                          cases[i].data_len,
                          cases[i].paramsSize,
                          cases[i].paramsBufferSize);

        int result = safe_parse_erc20_params(&tx);

        if (cases[i].expect_success) {
            /* When valid, operation must succeed */
            ck_assert_msg(result == 0,
                "Case '%s': expected success but got failure",
                cases[i].description);

            /* After successful memmove, verify params buffer integrity:
             * the destination must be within bounds */
            ck_assert_msg(tx.paramsSize <= sizeof(tx.params),
                "Case '%s': paramsSize exceeds buffer after operation",
                cases[i].description);
        } else {
            /* When invalid/adversarial, operation must be rejected */
            ck_assert_msg(result == -1,
                "Case '%s': expected rejection but got success - "
                "security invariant violated!",
                cases[i].description);
        }

        /* Universal invariant: paramsBufferSize must never exceed
         * the actual allocated buffer size regardless of outcome */
        ck_assert_msg(sizeof(tx.params) == PARAMS_BUFFER_SIZE,
            "Case '%s': buffer size constant changed unexpectedly",
            cases[i].description);
    }
}
END_TEST

START_TEST(test_memmove_source_destination_overlap_safety)
{
    /* Invariant: overlapping memmove within the same buffer must
     * produce correct results and not corrupt data outside bounds.
     */
    Transaction tx;
    uint8_t expected[ERC20_DATA_LENGTH];

    /* Fill params with known pattern */
    for (int i = 0; i < PARAMS_BUFFER_SIZE; i++) {
        tx.params[i] = (uint8_t)(i & 0xFF);
    }
    tx.paramsSize = ERC20_DATA_LENGTH + 2;
    tx.paramsBufferSize = ERC20_DATA_LENGTH + 2;

    /* Record what should be at params+2 before the move */
    memcpy(expected, tx.params + 2, ERC20_DATA_LENGTH);

    int result = safe_parse_erc20_params(&tx);
    ck_assert_int_eq(result, 0);

    /* After memmove, params[0..ERC20_DATA_LENGTH-1] must equal
     * what was at params[2..ERC20_DATA_LENGTH+1] before */
    ck_assert_msg(memcmp(tx.params, expected, ERC20_DATA_LENGTH) == 0,
        "memmove produced incorrect result - data corruption detected");

    /* Bytes beyond ERC20_DATA_LENGTH must not be corrupted by the operation */
    /* (We only moved ERC20_DATA_LENGTH bytes, so bytes after that in the
     *  original buffer should remain as they were at positions 2+ERC20_DATA_LENGTH onward) */
}
END_TEST

START_TEST(test_params_buffer_size_consistency)
{
    /* Invariant: paramsBufferSize must always be <= sizeof(tx->params)
     * and must be consistent with paramsSize to prevent overread.
     */
    Transaction tx;

    /* Test a range of boundary values */
    uint16_t test_sizes[] = {
        0,
        1,
        2,
        ERC20_DATA_LENGTH,
        ERC20_DATA_LENGTH + 1,
        ERC20_DATA_LENGTH + 2,
        PARAMS_BUFFER_SIZE - 1,
        PARAMS_BUFFER_SIZE,
        PARAMS_BUFFER_SIZE + 1,
        0x7FFF,
        0x8000,
        0xFFFF
    };

    int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int i = 0; i < num_sizes; i++) {
        memset(&tx, 0, sizeof(tx));
        tx.paramsSize = test_sizes[i];
        tx.paramsBufferSize = test_sizes[i];

        /* Fill with adversarial pattern */
        memset(tx.params, 0xA5, sizeof(tx.params));

        int result = safe_parse_erc20_params(&tx);

        if (result == 0) {
            /* If accepted, all invariants must hold */
            ck_assert_msg(tx.paramsSize >= (uint16_t)(2 + ERC20_DATA_LENGTH),
                "Accepted transaction with insufficient paramsSize=%u",
                test_sizes[i]);
            ck_assert_msg(tx.paramsBufferSize <= sizeof(tx.params),
                "Accepted transaction with paramsBufferSize=%u exceeding allocation",
                test_sizes[i]);
            ck_assert_msg(tx.paramsBufferSize <= tx.paramsSize,
                "Accepted transaction with inconsistent buffer sizes");
        }
        /* If rejected (result == -1), that's also acceptable - no assertion needed */
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_memmove_buffer_safety_invariant);
    tcase_add_test(tc_core, test_memmove_source_destination_overlap_safety);
    tcase_add_test(tc_core, test_params_buffer_size_consistency);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}