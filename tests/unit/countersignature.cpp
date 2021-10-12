#include "../../src/countersignature.h"

#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>

TEST(CountersignatureModule, countersignature_array_insert)
{
    CountersignatureArray array = {
        .counters = nullptr,
        .count = 0,
    };

    Countersignature countersig1;

    int res = countersignature_array_insert(&array, &countersig1);
    EXPECT_EQ(res, 0);
    ASSERT_EQ(array.count, 1);
    ASSERT_TRUE(array.counters);
    EXPECT_EQ(array.counters[0], &countersig1);

    Countersignature countersig2;

    res = countersignature_array_insert(&array, &countersig2);
    EXPECT_EQ(res, 0);
    ASSERT_EQ(array.count, 2);
    ASSERT_TRUE(array.counters);
    EXPECT_EQ(array.counters[1], &countersig2);
}

TEST(CountersignatureModule, countersignature_array_move)
{
    CountersignatureArray array1 = {
        .counters = nullptr,
        .count = 0,
    };
    CountersignatureArray array2 = {
        .counters = nullptr,
        .count = 0,
    };

    Countersignature countersig1;
    Countersignature countersig2;

    int res = countersignature_array_insert(&array2, &countersig1);
    EXPECT_EQ(res, 0);

    res = countersignature_array_insert(&array2, &countersig2);
    EXPECT_EQ(res, 0);

    res = countersignature_array_move(&array1, &array2);
    EXPECT_EQ(res, 0);

    ASSERT_TRUE(array1.counters);
    ASSERT_EQ(array1.count, 2);

    EXPECT_EQ(array1.counters[0], &countersig1);
    EXPECT_EQ(array1.counters[1], &countersig2);

    EXPECT_EQ(array2.count, 0);
    EXPECT_FALSE(array2.counters);
}