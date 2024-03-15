/*
 * Copyright (C) 2024 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <gtest/gtest.h>
#include "Utils/Optional.h"

using namespace intel::sgx::dcap;

struct TestObject
{
    int x;
    bool operator==(const TestObject& other) const
    {
        return x == other.x;
    }
};

TEST(OptionalUT, HasValue)
{
    TestObject t{10};
    Optional<TestObject> opt(t);
    EXPECT_TRUE(opt.has_value());
}

TEST(OptionalUT, Value)
{
    TestObject t{10};
    Optional<TestObject> opt(t);
    EXPECT_EQ(opt.value(), t);
}

TEST(OptionalUT, OperatorNot)
{
    TestObject t{10};
    Optional<TestObject> opt(t);
    EXPECT_FALSE(!opt);
}

TEST(OptionalUT, OperatorArrow)
{
    TestObject t{10};
    Optional<TestObject> opt(t);
    EXPECT_EQ(opt->x, t.x);
}

TEST(OptionalUT, OperatorEqual)
{
    TestObject t1{10};
    TestObject t2{10};
    Optional<TestObject> opt1(t1);
    Optional<TestObject> opt2(t2);
    EXPECT_TRUE(opt1 == opt2);
    EXPECT_TRUE(opt1 == t2);
}

TEST(OptionalUT, OperatorNotEqual)
{
    TestObject t1{10};
    TestObject t2{20};
    Optional<TestObject> opt1(t1);
    Optional<TestObject> opt2(t2);
    EXPECT_TRUE(opt1 != opt2);
    EXPECT_TRUE(opt1 != t2);
}

TEST(OptionalUT, DefaultConstructor)
{
    Optional<TestObject> opt;
    EXPECT_FALSE(opt.has_value());
}

TEST(OptionalUT, ValueConstructor)
{
    TestObject t{10};
    Optional<TestObject> opt(t);
    EXPECT_TRUE(opt.has_value());
    EXPECT_EQ(opt.value(), t);
}

TEST(OptionalUT, CopyConstructor)
{
    TestObject t{10};
    Optional<TestObject> opt1(t);
    Optional<TestObject> opt2(opt1);
    EXPECT_EQ(opt1, opt2);
}

TEST(OptionalUT, CopyAssignment)
{
    TestObject t{10};
    Optional<TestObject> opt1(t);
    Optional<TestObject> opt2;
    opt2 = opt1;
    EXPECT_EQ(opt1, opt2);
}

TEST(OptionalUT, MoveConstructor)
{
    TestObject t{10};
    Optional<TestObject> opt1(t);
    Optional<TestObject> opt2(std::move(opt1));
    EXPECT_EQ(opt2.value(), t);
    EXPECT_FALSE(opt1.has_value());
}

TEST(OptionalUT, MoveAssignment)
{
    TestObject t{10};
    Optional<TestObject> opt1(t);
    Optional<TestObject> opt2;
    opt2 = std::move(opt1);
    EXPECT_EQ(opt2.value(), t);
    EXPECT_FALSE(opt1.has_value());
}

TEST(OptionalUT, ValueException)
{
    Optional<TestObject> opt;
    EXPECT_THROW(opt.value(), std::logic_error);
}

TEST(OptionalUT, ArrowException)
{
    Optional<TestObject> opt;
    EXPECT_THROW(opt.operator->(), std::logic_error);
}

TEST(OptionalUT, NotEqual)
{
    TestObject t1{10};
    TestObject t2{20};
    Optional<TestObject> opt1(t1);
    Optional<TestObject> opt2(t2);
    EXPECT_NE(opt1, opt2);
    EXPECT_NE(opt1, t2);
}

TEST(OptionalUT, CopyConstructorNoValue)
{
    Optional<TestObject> opt1;
    Optional<TestObject> opt2(opt1);
    EXPECT_FALSE(opt2.has_value());
}