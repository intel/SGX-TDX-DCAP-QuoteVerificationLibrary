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

#ifndef SGXECDSAATTESTATION_OPTIONAL_H
#define SGXECDSAATTESTATION_OPTIONAL_H

#include <stdexcept>

namespace intel::sgx::dcap {

    // We implement our own Optional type as Windows SGX SDK doesn't support std::optional
    template <typename T> class Optional {
    private:
        T* internalValue;
        bool hasValue;

    public:
        Optional() : internalValue(nullptr), hasValue(false) {}

        Optional(const T& val) : internalValue(new T(val)), hasValue(true) {}

        Optional(const Optional& other) : hasValue(other.hasValue)
        {
            if (hasValue)
            {
                internalValue = new T(*other.internalValue);
            }
            else
            {
                internalValue = nullptr;
            }
        }

        Optional& operator=(const Optional& other)
        {
            if (&other != this)
            {
                delete internalValue;
                hasValue = other.hasValue;
                if (hasValue)
                {
                    internalValue = new T(*other.internalValue);
                }
            }
            return *this;
        }

        Optional(Optional&& other) noexcept : internalValue(other.internalValue), hasValue(other.hasValue)
        {
            other.internalValue = nullptr;
            other.hasValue = false;
        }

        Optional& operator=(Optional&& other) noexcept
        {
            if (&other != this)
            {
                delete internalValue;
                internalValue = other.internalValue;
                hasValue = other.hasValue;
                other.internalValue = nullptr;
                other.hasValue = false;
            }
            return *this;
        }

        ~Optional()
        {
            if (internalValue != nullptr) {
                delete internalValue;
            }
        }

        bool has_value() const
        {
            return hasValue;
        }

        T value() const
        {
            if (hasValue)
            {
                return *internalValue;
            }
            else
            {
                throw std::logic_error("Bad Optional Access");
            }
        }

        bool operator!() const
        {
            return !hasValue;
        }

        T* operator->() const
        {
            if (hasValue)
            {
                return internalValue;
            }
            else
            {
                throw std::logic_error("Bad Optional Access");
            }
        }

        bool operator==(const Optional<T>& other) const
        {
            if (hasValue != other.hasValue)
            {
                return false;
            }
            if (!hasValue)
            {
                return true;
            }
            return *internalValue == *other.internalValue;
        }

        bool operator==(const T& val) const
        {
            if (!hasValue)
            {
                return false;
            }
            return *internalValue == val;
        }

        bool operator!=(const Optional<T>& other) const
        {
            return !(*this == other);
        }

        bool operator!=(const T& val) const
        {
            return !(*this == val);
        }
    };
}
#endif //SGXECDSAATTESTATION_OPTIONAL_H
